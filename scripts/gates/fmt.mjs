import { run } from "./common.mjs";
try {
  run("cargo", ["fmt", "--all", "--", "--check"]);
  console.log("GETTER_GATE_FMT_PASS");
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
