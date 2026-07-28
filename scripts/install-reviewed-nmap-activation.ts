#!/usr/bin/env bun

import { resolve } from "node:path";
import { queryActiveV2Work } from "./release/FunctionalReleasePrimitives";
import { AuthenticatedNmapActivationVerifier } from "./release/AuthenticatedNmapActivationVerifier";
import {
  installedFileIdentity,
  NMAP_ACTIVATION_SERVICE_UNIT,
  NmapActivationBundleInstaller,
  type NmapBinaryIdentity,
  type ReviewedNmapInstallerPort,
  type TiScaleServiceController,
  type TiScaleServiceIdentity,
} from "./release/NmapActivationBundle";

const SOURCE_ROOT = resolve(import.meta.dir, "..");
const DATABASE_PATH = "/var/lib/ti-scale/data/ti-scale.sqlite";
const SYSTEMCTL = "/usr/bin/systemctl";
const BASH = "/usr/bin/bash";
const GETCAP = "/usr/sbin/getcap";
const ID = "/usr/bin/id";

function runRequired(command: readonly string[]): string {
  const result = Bun.spawnSync([...command], {
    cwd: "/",
    env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    const reason = result.stderr.toString().trim().slice(0, 1_000);
    throw new Error(`${command[0]} failed${reason ? `: ${reason}` : ""}`);
  }
  return result.stdout.toString().trim();
}

function serviceIdentity(): TiScaleServiceIdentity {
  const output = runRequired([
    SYSTEMCTL,
    "show",
    NMAP_ACTIVATION_SERVICE_UNIT,
    "--property=Id",
    "--property=LoadState",
    "--property=ActiveState",
    "--property=MainPID",
    "--property=FragmentPath",
    "--no-pager",
  ]);
  const fields = Object.fromEntries(output.split("\n").map((line) => {
    const separator = line.indexOf("=");
    return separator < 1 ? [line, ""] : [line.slice(0, separator), line.slice(separator + 1)];
  }));
  return {
    id: fields.Id ?? "",
    loadState: fields.LoadState ?? "",
    activeState: fields.ActiveState ?? "",
    mainPid: Number(fields.MainPID ?? -1),
    fragmentPath: fields.FragmentPath ?? "",
  };
}

class ExactTiScaleSystemdController implements TiScaleServiceController {
  async identity(): Promise<TiScaleServiceIdentity> {
    return serviceIdentity();
  }

  async stop(unit: typeof NMAP_ACTIVATION_SERVICE_UNIT): Promise<void> {
    if (unit !== NMAP_ACTIVATION_SERVICE_UNIT) throw new Error("Refusing to stop any service except ti-scale.service");
    runRequired([SYSTEMCTL, "stop", NMAP_ACTIVATION_SERVICE_UNIT]);
  }

  async daemonReload(): Promise<void> {
    runRequired([SYSTEMCTL, "daemon-reload"]);
  }

  async start(unit: typeof NMAP_ACTIVATION_SERVICE_UNIT): Promise<void> {
    if (unit !== NMAP_ACTIVATION_SERVICE_UNIT) throw new Error("Refusing to start any service except ti-scale.service");
    runRequired([SYSTEMCTL, "start", NMAP_ACTIVATION_SERVICE_UNIT]);
  }
}

class ExactReviewedNmapInstaller implements ReviewedNmapInstallerPort {
  #identity(): NmapBinaryIdentity {
    const path = "/opt/ti-scale-toolchain/nmap/5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f/nmap";
    const capabilities = runRequired([GETCAP, "-n", "--", path]);
    return installedFileIdentity(path, capabilities);
  }

  async install(installerPath: string): Promise<NmapBinaryIdentity> {
    runRequired([BASH, installerPath, "install"]);
    return this.#identity();
  }

  async verify(installerPath: string): Promise<NmapBinaryIdentity> {
    runRequired([BASH, installerPath, "verify"]);
    return this.#identity();
  }
}

function requireRoot(): void {
  if ((process.geteuid?.() ?? process.getuid?.() ?? -1) !== 0) {
    throw new Error("The reviewed Nmap activation installer must run as root");
  }
}

function serviceGid(): number {
  const gid = Number(runRequired([ID, "-g", "ti-scale"]));
  if (!Number.isSafeInteger(gid) || gid <= 0) throw new Error("Could not resolve the ti-scale service group");
  return gid;
}

async function main(): Promise<void> {
  requireRoot();
  const operation = process.argv[2];
  if (operation !== "verify") {
    throw new Error(
      `No-backup policy permits only: ${process.argv[1]} verify`,
    );
  }
  if (process.argv.length !== 3) throw new Error("verify accepts no additional arguments");
  const installer = new NmapActivationBundleInstaller({
    sourceRoot: SOURCE_ROOT,
    installedGroupGid: serviceGid(),
    readActiveWork: () => queryActiveV2Work(DATABASE_PATH),
    nmapInstaller: new ExactReviewedNmapInstaller(),
    service: new ExactTiScaleSystemdController(),
    postStartVerifier: new AuthenticatedNmapActivationVerifier(),
  });
  const result = await installer.verify();
  process.stdout.write(`${result.status}: ${result.bundleVersion}; service boundary ${result.controlsOnly}\n`);
}

if (import.meta.main) {
  main().catch((error: unknown) => {
    process.stderr.write(`Reviewed Nmap activation failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
    process.exitCode = 1;
  });
}
