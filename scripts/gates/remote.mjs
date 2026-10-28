import { spawnSync } from "node:child_process";

function git(args) {
  const result = spawnSync("git", args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `git ${args.join(" ")} failed`);
  }
  return result.stdout.trim();
}

try {
  const head = git(["rev-parse", "HEAD"]);
  const branch = git(["rev-parse", "--abbrev-ref", "HEAD"]);
  if (branch !== "main") throw new Error(`expected branch main, found ${branch}`);
  const remote = git(["ls-remote", "origin", "refs/heads/main"])
    .split(/\s+/)[0]
    .trim();
  if (!remote) throw new Error("origin has no main branch");
  if (head !== remote) {
    throw new Error(`remote main ${remote} does not match local ${head}; push before reporting completion`);
  }
  const status = git(["status", "--porcelain"]);
  if (status !== "") {
    throw new Error(`working tree is not clean:\n${status}`);
  }
  console.log(`GETTER_GATE_REMOTE_PASS commit=${head}`);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
