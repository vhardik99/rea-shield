import fs from "node:fs/promises";
import path from "node:path";

export async function readText(file) {
  return fs.readFile(file, "utf8");
}

export async function writeJson(file, value) {
  const target = path.resolve(file);
  await fs.mkdir(path.dirname(target), { recursive: true });
  const temp = `${target}.${process.pid}.tmp`;
  await fs.writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await fs.rename(temp, target);
}

export function parseJson(text, label) {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
}

export function parseArgs(args) {
  const positional = [];
  const options = {};
  for (let i = 0; i < args.length; i += 1) {
    const item = args[i];
    if (item === "--help" || item === "-h") {
      options.help = true;
    } else if (item.startsWith("--")) {
      const key = item.slice(2);
      const next = args[i + 1];
      if (!next || next.startsWith("--")) {
        throw new Error(`Option --${key} requires a value`);
      }
      options[key] = next;
      i += 1;
    } else {
      positional.push(item);
    }
  }
  return { positional, options };
}

export function finiteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}
