import { run } from "./common.mjs";
import process from "node:process";

try {
  // Prove dependency resolution and library tests do not need the network.
  run("cargo", ["metadata", "--locked", "--offline", "--format-version", "1"], {
    stdio: "ignore",
    env: { CARGO_NET_OFFLINE: "true" },
  });
  run("cargo", ["test", "--quiet", "--locked", "--offline", "--workspace", "--lib"], {
    env: { CARGO_NET_OFFLINE: "true" },
  });
  // The full workflow uses only loopback. Force any accidental external HTTP
  // through a dead proxy while exempting loopback addresses.
  run("bash", ["scripts/e2e-local.sh"], {
    env: {
      CARGO_NET_OFFLINE: "true",
      GETTER_BIN: `${process.cwd()}/target/release/getter`,
      HTTP_PROXY: "http://127.0.0.1:9",
      HTTPS_PROXY: "http://127.0.0.1:9",
      ALL_PROXY: "http://127.0.0.1:9",
      NO_PROXY: "127.0.0.1,localhost,::1",
    },
  });
  console.log("GETTER_GATE_OFFLINE_PASS");
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
