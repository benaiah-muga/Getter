import { run } from "./common.mjs";

try {
  run("cargo", ["build", "--locked", "-p", "getter-cli", "--release"]);
  run("bash", ["scripts/e2e-local.sh"], {
    env: { GETTER_BIN: `${process.cwd()}/target/release/getter` },
  });
  console.log("GETTER_E2E_PASS");
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
