import { run } from "./common.mjs";
try {
  run("cargo", ["clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"]);
  console.log("GETTER_GATE_CLIPPY_PASS");
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
