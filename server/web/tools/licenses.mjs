import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const output = resolve(root, "../internal/webui/dist");
const lock = JSON.parse(
  readFileSync(resolve(root, "package-lock.json"), "utf8"),
);
const notices = [
  "NetHub console third-party notices\n",
  readFileSync(resolve(root, "THIRD_PARTY_LICENSE.txt"), "utf8"),
];
for (const [name, info] of Object.entries(lock.packages)) {
  if (!name || info.dev || (info.optional && !name.startsWith("node_modules/")))
    continue;
  const folder = resolve(root, name);
  if (
    !folder.startsWith(resolve(root, "node_modules") + "/") &&
    !folder.startsWith(resolve(root, "node_modules") + "\\")
  )
    throw new Error("Unexpected package path");
  const files = readdirSync(folder).filter((file) =>
    /^(licen[cs]e|copying|notice)(\.|$)/i.test(file),
  );
  if (!files.length) throw new Error(`Missing runtime license: ${name}`);
  notices.push(`\n--- ${name} ${info.version} ---\n`);
  for (const file of files)
    notices.push(readFileSync(resolve(folder, file), "utf8"));
}
writeFileSync(resolve(output, "third-party-licenses.txt"), notices.join("\n"));
writeFileSync(resolve(output, ".gitkeep"), "");
