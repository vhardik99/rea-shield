import fs from "node:fs/promises";
import path from "node:path";
import { parse } from "@babel/parser";
import generateModule from "@babel/generator";
import traverseModule from "@babel/traverse";
import * as t from "@babel/types";

const generate = generateModule.default ?? generateModule;
const traverse = traverseModule.default ?? traverseModule;

function expressionToBytecode(node, params, code) {
  if (t.isNumericLiteral(node)) {
    code.push(["const", node.value]);
    return true;
  }
  if (t.isIdentifier(node) && params.has(node.name)) {
    code.push(["arg", params.get(node.name)]);
    return true;
  }
  if (t.isUnaryExpression(node, { operator: "-" })) {
    if (!expressionToBytecode(node.argument, params, code)) return false;
    code.push(["neg"]);
    return true;
  }
  if (t.isBinaryExpression(node) && ["+", "-", "*", "/"].includes(node.operator)) {
    if (!expressionToBytecode(node.left, params, code)) return false;
    if (!expressionToBytecode(node.right, params, code)) return false;
    code.push([node.operator]);
    return true;
  }
  return false;
}

function vmExpression(bytecode, argsExpression) {
  const bytecodeNode = t.valueToNode(bytecode);
  const stackName = "_s";
  const insName = "_i";
  const opName = "_o";
  const leftName = "_a";
  const rightName = "_b";
  const argName = "_args";
  const body = t.blockStatement([
    t.variableDeclaration("const", [
      t.variableDeclarator(t.identifier(argName), argsExpression),
      t.variableDeclarator(t.identifier(stackName), t.arrayExpression([]))
    ]),
    t.forOfStatement(
      t.variableDeclaration("const", [t.variableDeclarator(t.identifier(insName))]),
      bytecodeNode,
      t.blockStatement([
        t.variableDeclaration("const", [
          t.variableDeclarator(t.identifier(opName), t.memberExpression(t.identifier(insName), t.numericLiteral(0), true))
        ]),
        t.ifStatement(
          t.binaryExpression("===", t.identifier(opName), t.stringLiteral("const")),
          t.expressionStatement(t.callExpression(t.memberExpression(t.identifier(stackName), t.identifier("push")), [
            t.memberExpression(t.identifier(insName), t.numericLiteral(1), true)
          ])),
          t.ifStatement(
            t.binaryExpression("===", t.identifier(opName), t.stringLiteral("arg")),
            t.expressionStatement(t.callExpression(t.memberExpression(t.identifier(stackName), t.identifier("push")), [
              t.memberExpression(t.identifier(argName), t.memberExpression(t.identifier(insName), t.numericLiteral(1), true), true)
            ])),
            t.ifStatement(
              t.binaryExpression("===", t.identifier(opName), t.stringLiteral("neg")),
              t.blockStatement([
                t.expressionStatement(t.assignmentExpression("=", t.memberExpression(t.identifier(stackName), t.binaryExpression("-", t.memberExpression(t.identifier(stackName), t.identifier("length")), t.numericLiteral(1)), true), t.unaryExpression("-", t.memberExpression(t.identifier(stackName), t.binaryExpression("-", t.memberExpression(t.identifier(stackName), t.identifier("length")), t.numericLiteral(1)), true))))
              ]),
              t.blockStatement([
                t.variableDeclaration("const", [
                  t.variableDeclarator(t.identifier(leftName), t.callExpression(t.memberExpression(t.identifier(stackName), t.identifier("pop")), [])),
                  t.variableDeclarator(t.identifier(rightName), t.callExpression(t.memberExpression(t.identifier(stackName), t.identifier("pop")), []))
                ]),
                t.expressionStatement(t.callExpression(t.memberExpression(t.identifier(stackName), t.identifier("push")), [
                  t.conditionalExpression(
                    t.binaryExpression("===", t.identifier(opName), t.stringLiteral("+")),
                    t.binaryExpression("+", t.identifier(rightName), t.identifier(leftName)),
                    t.conditionalExpression(
                      t.binaryExpression("===", t.identifier(opName), t.stringLiteral("-")),
                      t.binaryExpression("-", t.identifier(rightName), t.identifier(leftName)),
                      t.conditionalExpression(
                        t.binaryExpression("===", t.identifier(opName), t.stringLiteral("*")),
                        t.binaryExpression("*", t.identifier(rightName), t.identifier(leftName)),
                        t.binaryExpression("/", t.identifier(rightName), t.identifier(leftName))
                      )
                    )
                  )
                ]))
              ])
            )
          )
        )
      ])
    ),
    t.returnStatement(t.memberExpression(t.identifier(stackName), t.numericLiteral(0), true))
  ]);
  return t.callExpression(t.arrowFunctionExpression([], body), []);
}

export function protectSource(source, filename = "input.js") {
  const ast = parse(source, {
    sourceType: "unambiguous",
    sourceFilename: filename,
    plugins: ["jsx", "typescript", "decorators-legacy", "classProperties", "topLevelAwait"]
  });
  const transformed = [];
  const exclusions = [];

  traverse(ast, {
    FunctionDeclaration(pathRef) {
      const node = pathRef.node;
      const comments = [...(node.leadingComments ?? []), ...(pathRef.parentPath?.node?.leadingComments ?? [])];
      if (!comments.some((comment) => /@rea-protect\b/.test(comment.value))) return;
      const name = node.id?.name ?? "(anonymous)";
      if (!node.id || node.async || node.generator || node.params.some((param) => !t.isIdentifier(param))) {
        exclusions.push({ name, line: node.loc?.start.line ?? null, reason: "Only named, synchronous functions with simple identifier parameters are supported." });
        return;
      }
      if (node.body.body.length !== 1 || !t.isReturnStatement(node.body.body[0]) || !node.body.body[0].argument) {
        exclusions.push({ name, line: node.loc?.start.line ?? null, reason: "Function body must contain exactly one return expression." });
        return;
      }
      const params = new Map(node.params.map((param, index) => [param.name, index]));
      const bytecode = [];
      if (!expressionToBytecode(node.body.body[0].argument, params, bytecode)) {
        exclusions.push({ name, line: node.loc?.start.line ?? null, reason: "Expression uses unsupported syntax; supported subset is numeric literals, parameters, unary minus, and + - * /." });
        return;
      }
      const args = t.arrayExpression(node.params.map((param) => t.identifier(param.name)));
      node.body.body[0].argument = vmExpression(bytecode, args);
      transformed.push({ name, line: node.loc?.start.line ?? null, operations: bytecode.length });
    }
  });

  return {
    code: generate(ast, { comments: true, compact: false, retainLines: false }, source).code + "\n",
    report: {
      version: "0.4.0",
      file: filename,
      transformed,
      exclusions,
      warning: "This transformation is not a cryptographic boundary. Client-side code can be inspected by a sufficiently capable attacker."
    }
  };
}

export async function protectFile(filename, output) {
  const input = path.resolve(filename);
  const target = path.resolve(output ?? path.join(path.dirname(input), `protected_${path.basename(input)}`));
  const result = protectSource(await fs.readFile(input, "utf8"), input);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, result.code, "utf8");
  return { ...result.report, output: target };
}
