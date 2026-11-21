import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { appendFileSync, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync,
  statSync,
  realpathSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

const git = (cwd: string, args: string[]): string =>
  execFileSync("git", ["-c", "core.hooksPath=/dev/null", ...args], {
    cwd, encoding: "utf8", maxBuffer: 4 * 1024 * 1024 }).trim();
const sourcePath = (path: string): boolean =>
  /^(apps|packages|tests|scripts|rules|fixtures|docs)\//.test(path) ||
  [".gitignore", "package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml",
    "tsconfig.json"].includes(path);

/** Captures the current local source as a clean, private lab-only Git base. */
export function prepareLabCodeCheckout(repoRoot: string, dataDir: string): string {
  const source = realpathSync(resolve(repoRoot));
  const data = realpathSync(resolve(dataDir));
  if (readFileSync(join(data, "fault-lab.marker"), "utf8") !==
    "banco-vivo-fault-lab-v1\n") throw new Error("FAULT_LAB_CODE_MARKER_INVALID");
  const destination = join(data, "code-checkout");
  if (existsSync(destination)) {
    if (!lstatSync(destination).isDirectory() ||
      git(destination, ["rev-parse", "--show-toplevel"]) !==
        realpathSync(destination) ||
      readFileSync(join(destination, ".lab-code-source"), "utf8") !==
        source + "\n") throw new Error("FAULT_LAB_CODE_CHECKOUT_INVALID");
    return realpathSync(destination);
  }
  const nodeModules = join(source, "node_modules");
  if (!existsSync(nodeModules) || !statSync(nodeModules).isDirectory())
    throw new Error("FAULT_LAB_CODE_DEPENDENCIES_MISSING");
  const staging = join(data, `code-checkout-${randomUUID()}.tmp`);
  mkdirSync(staging, { mode: 0o700 });
  try {
    const files = execFileSync("git", ["ls-files", "-z", "--cached", "--others",
      "--exclude-standard"], { cwd: source, maxBuffer: 4 * 1024 * 1024 })
      .toString("utf8").split("\0").filter(Boolean);
    for (const path of files) {
      if (!sourcePath(path)) continue;
      const from = resolve(source, path);
      if (!from.startsWith(`${source}${sep}`) ||
        relative(source, from).startsWith(".."))
        throw new Error("FAULT_LAB_CODE_PATH_INVALID");
      if (!existsSync(from)) continue;
      if (!lstatSync(from).isFile() || realpathSync(from) !== from)
        throw new Error("FAULT_LAB_CODE_SOURCE_NOT_REGULAR");
      const to = join(staging, path);
      mkdirSync(dirname(to), { recursive: true });
      copyFileSync(from, to);
    }
    writeFileSync(join(staging, ".lab-code-source"), source + "\n",
      { mode: 0o600 });
    git(staging, ["init", "-q"]);
    git(staging, ["add", "-A"]);
    git(staging, ["-c", "user.name=Banco Vivo Lab",
      "-c", "user.email=lab@banco-vivo.invalid", "commit", "-qm",
      "Local lab source snapshot"]);
    appendFileSync(join(staging, ".git/info/exclude"), "\nnode_modules\n");
    symlinkSync(nodeModules, join(staging, "node_modules"), "dir");
    renameSync(staging, destination);
    return realpathSync(destination);
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  }
}
