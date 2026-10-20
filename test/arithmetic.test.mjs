// test/arithmetic.test.mjs
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import { protectSource, protectFile } from '../src/protect.mjs';
import { pathToFileURL } from 'node:url';

const tmpDir = path.join(process.cwd(), '.tmp_test_arith');
await fs.mkdir(tmpDir, { recursive: true });

const sourcePath = path.join(tmpDir, 'source.mjs');
const sourceCode = `
// @rea-protect
export function compute(x, y) {
  return x + y * 2 - 3 / (x - 1) + -5 + 0.5;
}
`;
await fs.writeFile(sourcePath, sourceCode, 'utf8');

// Use protectFile to transform the source file
const result = await protectFile(sourcePath);
const { transformed, output } = result;
assert(transformed.length === 1, 'function should be transformed');
const protectedPath = output;

const originalModule = await import(pathToFileURL(sourcePath).href);
const protectedModule = await import(pathToFileURL(protectedPath).href);

const testVectors = [
  [2, 3],
  [5, 0],
  [1.5, -2.5]
];

for (const [x, y] of testVectors) {
  const original = originalModule.compute(x, y);
  const transformed = protectedModule.compute(x, y);
  assert(Math.abs(original - transformed) < 1e-9, `Mismatch for (${x}, ${y})`);
}

test('Arithmetic transformation matches original behavior', () => {
  // No additional assertions needed; earlier asserts will throw on failure.
});
