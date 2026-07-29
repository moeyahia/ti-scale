# Reviewed Nmap TCP-connect capability and Autonomous Safe Recon activation

Ti-Scale contains a disabled-by-default Guided capability for a bounded TCP
connect and light service-version scan. It does not use raw sockets, Linux file
capabilities, a shell, Nmap scripts, OS detection, UDP, host ranges, CIDRs, or
runtime-selected flags.

## Why the distribution executable is not used directly

The reviewed Kali Nmap 7.99 executable at `/usr/lib/nmap/nmap` has SHA-256
`5b42c994b6f5804be11726deae943defc868dbe91d8362b3a2686b7d5160667f` and
Linux file capabilities `cap_net_bind_service,cap_net_admin,cap_net_raw=eip`.
Linux refuses to execute that file when Ti-Scale runs with `NoNewPrivileges`
and an empty capability bounding set. The `/usr/bin/nmap` wrapper reaches the
same executable and fails for the same reason.

The installation script copies the reviewed bytes into the stable, versioned
`/opt/ti-scale-toolchain` root without touching Ti-Scale's atomically swapped
immutable release tree. It installs without extended capabilities and verifies the source and
destination SHA-256, root ownership, mode `0555`, an empty file-capability set,
and a target-free `--version` probe under the `ti-scale` service identity with
`NoNewPrivileges` and no inherited, ambient, or bounding capabilities.
Installing the reviewed executable alone grants no mission authority. The
disabled manifest remains authoritative until the separately reviewed,
frozen activation bundle is applied and its post-start readiness proof passes.
The execution and target-free probe sandboxes expose only the selected
read-only `libblas.so.3` alternative needed by Kali's dynamic loader; they do
not expose the host alternatives directory or broaden filesystem writes.

## Reviewed activation bundle

The repository contains a complete, versioned activation bundle. Merely
checking out these files does not install Nmap, edit `/etc`, restart a service,
or grant mission authority.

| Source | Reviewed SHA-256 |
| --- | --- |
| `deployment/runtime-config/nmap-activation-bundle.v1.json` | `2d78bae8c68961a95d63fc6483b77fc83c0acd7ce9024d1435fd6a0152ba04f4` |
| `deployment/runtime-config/local-tool-capabilities.nmap-enabled.v1.json` | `8a0ac74f4ef2f1988e4725e866d02c262b1875c1eee401f3cca0ce9e10766616` |
| `deployment/runtime-config/bubblewrap-probe-sandbox.v1.json` | `c715dd5706e91a416367eeac5512fba3c2a145a49fb8fc0778c9e8f2d8d457b9` |
| `deployment/runtime-config/engagement-workspace-mappings.v1.json` | `0ddf4173205c8d6d7a98dcfabd029a0d1baada653444b689c18853d509a688d1` |
| `deployment/runtime-config/autonomous-dns-local-runtime.v1.json` | `12770b66e7d46f8a9043439af3194ed4c478812fa0ffbdd6f6402719fc5116b7` |
| `deployment/runtime-config/nmap-activation-environment.v3.conf` | `5583dd2ed2270466d3db027a3d5574b0555680f4549782b66ccaab4f5540f36c` |
| `deployment/systemd/ti-scale.service.d/60-reviewed-nmap-activation.conf` | `c90baf171ddb9976fa4c8f726b5238960638cfe0dc30f8e739f55f5a890b9abd` |
| `scripts/install-reviewed-nmap.sh` | `34539a01da5776d18ced014798b2f71c7846d1d597248fc7650ca363e3bf65fc` |

The deployment-pinned Autonomous configuration preserves the DNS A-query
binding and adds a two-step single-host IP route: two bounded ICMP probes,
followed by a TCP-connect Nmap service scan over exactly these 14 reviewed
ports: `22,53,80,88,135,139,389,443,445,636,3389,5985,8080,8443`. All three
bindings share one deterministic policy, provider, specialist, model-policy
receipt, workspace boundary, and result sink. Activation fails closed unless
the `host`, `ping`, and capability-free Nmap executables all have current,
matching receipts.

The enabled manifest is a full independent document with manifest version
`kali-local-nmap-enabled-2026.07.20-v1`. Compared with the disabled baseline,
its only semantic changes are that exact Nmap binding's activation state and
reason plus the new manifest version.

The original activation bundle implementation documented a mutating
installation sequence. Ti-Scale now operates under a forward-only, no-backup
policy: the public command accepts `verify` only. `install`, `rollback`,
`--execute`, and `--confirm` are rejected before any service or filesystem
operation.

Read-only verification performs these operations:

1. re-verifies every source byte, mode, owner, path component, and non-symlink
   identity against the descriptor;
2. re-verifies the capability-free executable without installing it;
3. accepts either the original exact activation environment or the one
   reviewed Full-TCP forward composition;
4. for that forward composition, requires activation-environment SHA-256
   `e5626e1ab932b16d5a6dc8b946f7f754cbb2952d81eda977ff25d556071749f3`,
   manifest SHA-256
   `03f40b824e948aa9110ad40210933ef0b15a553d695af183154221ad7c40a848`,
   and runtime SHA-256
   `b8bfad3aa83aff4bc8ea95835e5bfdde1d199fec86b1795d63f0c5c6482af5f4`;
5. verifies root ownership, the `ti-scale` group, exact modes, colocated
   child-document paths, the enabled reviewed Nmap executable binding, and the
   Full-TCP runtime binding;
6. proves the exact loaded `ti-scale.service` identity without controlling it;
7. waits within a bounded interval for loopback HTTP, database, and event
   stream health; and
8. reads the operator token only from its private root-owned file, calls the
   authenticated read-only capability self-test, and accepts activation only
   when the exact Nmap tool and all seven joined dependencies are `pass`,
   `available`, and `fresh`.

The token is never printed, returned, written into a receipt, or stored in
browser or release state. The read buffer is cleared after the local request.

```bash
sudo /usr/local/bin/bun ./scripts/install-reviewed-nmap-activation.ts verify
```

Readiness remains unavailable unless the installed identity and the
operator-activation, executable-integrity, isolated target-free readiness,
direct-argv adapter, workspace confinement, result sink, and cancellation
requirements all share a current activation receipt.

## Runtime boundary

The represented Guided decision supplies exactly:

- one authorized normalized IP address or hostname;
- one canonical, ascending, duplicate-free comma-separated list of individual
  TCP ports; and
- one resolved mission workspace.

The list is limited to 1,024 ports and 4,096 characters. Ranges, CIDRs, host
sets, option injection, shell syntax, extra arguments, and changed parameters
are rejected. The fixed argv uses TCP connect scanning (`-sT`), disables name
resolution and host discovery, applies a 120-second host timeout, limits retry,
rate, parallelism, output, and total process time, and requests only light
service detection.

Raw stdout and stderr are retained as a private Engagement Log. A bounded
parser may create an unverified Observation containing ports, service labels,
and version hints. Neither raw output nor the parsed Observation is Verified
Evidence, and this binding does not automatically create an Evidence Candidate.

## Guided operator behavior

Guided intake may retain one optional, versioned first reconnaissance step.
The operator can choose a reviewed port preset or a custom validated list. The
selection persists independently of the transcript. The Commander exposes a
`Run this step` action only while this exact Nmap binding has current readiness;
otherwise it gives a safe, copyable manual procedure and does not dispatch.
One decision authorizes only its represented normalized target, port set, and
workspace. A materially changed action requires a new decision.

## Forward-only maintenance

There is no public rollback or backup path. A changed activation identity must
be introduced as a new, hash-pinned forward composition through the reviewed
release admission flow. The read-only Nmap command never rewrites `/etc`,
controls a service, or creates a restorable copy.
