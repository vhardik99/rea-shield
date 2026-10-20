#!/usr/bin/env node
import { runCli } from "../src/cli.mjs";

runCli(process.argv.slice(2)).catch((error) => {
  console.error(`[rea-shield] ${error?.message ?? String(error)}`);
  process.exitCode = 1;
});
