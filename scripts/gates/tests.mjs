import { run } from "./common.mjs";
try {
  run("cargo", ["test", "--locked", "--workspace", "--all-targets"]);
  console.log("GETTER_GATE_TESTS_PASS");
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
