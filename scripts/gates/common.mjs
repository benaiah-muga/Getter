import { spawnSync } from "node:child_process";
import process from "node:process";

export function run(command, args, options = {}) {
  process.stderr.write(`\n$ ${command} ${args.join(" ")}\n`);
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? process.cwd(),
    env: { ...process.env, ...(options.env ?? {}) },
    stdio: "inherit",
    shell: false,
  });
  if (result.error) {
    throw new Error(`could not start ${command}: ${result.error.message}`);
  }
  if (result.signal) {
    throw new Error(`${command} terminated by signal ${result.signal}`);
  }
  if (result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}`);
  }
  return result;
}
