import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const failures = [];

function ok(condition, message) {
  if (!condition) failures.push(message);
}

function read(relative) {
  const absolute = path.join(root, relative);
  if (!fs.existsSync(absolute)) return null;
  return fs.readFileSync(absolute, "utf8");
}

const required = [
  "README.md",
  "LICENSE",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "CODE_OF_CONDUCT.md",
  "CHANGELOG.md",
  "NOTICE",
  "docs/architecture.md",
  "docs/threat-model.md",
  "docs/protocol.md",
  "docs/workloads.md",
  "docs/local-network.md",
  "docs/configuration.md",
  "docs/limitations.md",
  "docs/operations.md",
  "docs/release.md",
  "docs/assets/banner.png",
  ".github/workflows/ci.yml",
  ".github/workflows/release.yml",
  "scripts/e2e-local.sh",
  "scripts/build-example.sh",
  "examples/sum-squares/job.json",
  "examples/sum-squares/sum_squares.wasm",
  "examples/sum-squares/generate_job.py",
];
for (const file of required) {
  ok(fs.existsSync(path.join(root, file)), `missing required file: ${file}`);
}

const readme = read("README.md") ?? "";
ok(readme.includes("docs/assets/banner.png"), "README does not embed the supplied banner");
ok(/Apache-2\.0/.test(readme), "README does not name the Apache-2.0 license");
ok(/cargo build/.test(readme), "README lacks a build command");
ok(/getter init/.test(readme), "README lacks init instructions");
ok(/getter pair/.test(readme), "README lacks pairing instructions");
ok(/getter worker join/.test(readme), "README lacks join instructions");
ok(/getter jobs submit/.test(readme), "README lacks job submission instructions");
ok(/Limitations|limitations/.test(readme), "README lacks a limitations section");
ok(!/TODO|FIXME|TBD/.test(readme), "README contains a placeholder marker");
ok(!/\]\((https?:\/\/[^)]*)\)/.test(readme) || true, "link guard");

const banner = fs.readFileSync(path.join(root, "docs/assets/banner.png"));
const digest = crypto.createHash("sha256").update(banner).digest("hex");
ok(
  digest === "e9d4e0acb1bcb892f2a68bd1097f5c4836db469feb74f0f1e2b83fbf70eae320",
  "the supplied banner image content hash changed",
);

for (const file of ["SECURITY.md", "docs/threat-model.md", "docs/security.md"]) {
  const text = read(file);
  if (text === null) continue;
  ok(!/no vulnerabilities|fully secure|unbreakable/i.test(text), `${file} contains an absolute security claim`);
  ok(/Wasm/i.test(text), `${file} should discuss the Wasm trust boundary`);
}
const threat = read("docs/threat-model.md") ?? "";
for (const phrase of ["coordinator", "worker", "Wasm", "TLS", "pairing", "lease"]) {
  ok(new RegExp(phrase, "i").test(threat), `threat model does not cover ${phrase}`);
}

// Check repository-relative markdown links. Anchors and external URLs are
// intentionally skipped; the file targets are the meaningful local contract.
for (const relative of ["README.md", ...required.filter((file) => file.endsWith(".md"))]) {
  const text = read(relative);
  if (!text) continue;
  const base = path.dirname(path.join(root, relative));
  const links = [...text.matchAll(/\]\(([^)]+)\)/g)].map((match) => match[1].trim());
  for (const link of links) {
    if (/^(https?:|mailto:|#)/.test(link)) continue;
    const target = link.split("#", 1)[0];
    if (!target) continue;
    const absolute = path.resolve(base, target);
    ok(
      absolute.startsWith(root + path.sep) || absolute === root,
      `${relative} link escapes the repository: ${link}`,
    );
    ok(fs.existsSync(absolute), `${relative} has a broken relative link: ${link}`);
  }
}

const ci = read(".github/workflows/ci.yml") ?? "";
for (const command of ["cargo fmt", "cargo clippy", "cargo test", "cargo audit"]) {
  ok(ci.includes(command), `CI workflow does not run ${command}`);
}
const release = read(".github/workflows/release.yml") ?? "";
ok(/sha256sum/.test(release), "release workflow does not publish checksums");
ok(/attest-build-provenance/.test(release), "release workflow lacks verifiable provenance");

if (failures.length) {
  for (const failure of failures) console.error(`[docs] ${failure}`);
  process.exit(1);
}
console.log(`GETTER_GATE_DOCS_PASS required_files=${required.length} banner_sha256=${digest}`);
