# Exact-target exploit confinement activation

This bundle is an additive, disabled-by-default boundary for Autonomous
`ScriptArtifact` validation. It is not a general command runner.

The application writes one hash-pinned Python source file into the private
staging directory and sends a fixed protocol request over the root-owned Unix
socket. The broker accepts only the `ti-scale` peer UID. It derives every host
path and process argument from a bounded execution ID; callers cannot provide a
path, command, environment variable, shell fragment, or credential.

For each accepted request, the broker snapshots the reviewed source to a
root-owned file and launches one transient systemd cgroup. The cgroup has
`IPAddressDeny=any` and one exact `/32` or `/128` `IPAddressAllow` property for
each normalized authorized target. Bubblewrap exposes only `/usr`, runtime
libraries, a private `/proc` and `/dev`, the immutable script, and one writable
job workspace. The script receives only repeated `--target <IP>` arguments.
Target ports are deliberately not claimed as confined in V1.

Readiness is fail-closed. `ATTEST` hashes the broker, activation manifest,
Bubblewrap, and Python interpreter and then performs a live cgroup probe. The
probe must reach the explicitly allowed local address and fail to reach an
unlisted address. A separate unfiltered baseline first proves that the same
unlisted address was reachable, preventing an unrelated network outage from
being mistaken for a working cgroup deny rule. The application compares all
returned identities with the root-owned manifest and rejects stale or
digest-invalid receipts.

Cancellation writes a root-owned marker and synchronously stops the exact
transient unit. The broker does not acknowledge `CANCEL` until `systemctl stop`
has returned successfully. A failed stop returns a bounded
`cancellation_failed` protocol error without exposing process output, so the
application cannot mistake an unconfirmed termination for a completed
cancellation before creating its terminal run checkpoint.
`RuntimeMaxSec`, `LimitFSIZE`, memory, task, CPU, descriptor, and cgroup kill
limits bound execution. Standard output and error are private Engagement Log
files; they are never automatically promoted to evidence.

Build and verification (do not activate during an application release):

```sh
cc -O2 -fPIE -pie -Wl,-z,relro,-z,now \
  -Wall -Wextra -Werror \
  deployment/exact-target-sandbox/ti-scale-exact-target-broker.c \
  -lcrypto -o /tmp/ti-scale-exact-target-broker
sha256sum /tmp/ti-scale-exact-target-broker /usr/bin/bwrap /usr/bin/python3.13
systemd-analyze verify \
  deployment/exact-target-sandbox/ti-scale-exact-target-sandbox.socket \
  deployment/exact-target-sandbox/ti-scale-exact-target-sandbox@.service
```

Activation must install the compiled broker and manifest as root-owned,
non-writable files, create these exact directories, install both systemd units,
and start only the socket:

- `/var/lib/ti-scale/exploit-sandbox/staging` — `ti-scale:ti-scale`, `0700`
- `/var/lib/ti-scale/exploit-sandbox/jobs` — `root:ti-scale`, `0710`
- `/run/ti-scale-exact-target-sandbox/executions` — `root:ti-scale`, `0750`
- `/run/ti-scale-exact-target-sandbox/cancellations` — `root:root`, `0700`

The socket worker receives only `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, and
`CAP_FOWNER` so it can read the private staged source, create a root-owned
immutable snapshot, and hand sealed log files back to the service account. It
has no network address family except `AF_UNIX`, no ambient/file capabilities,
and no capability is passed into the transient script unit. The broker does not
use Docker, Kubernetes, a shell, or public providers. The application must not advertise
`exploit_validation` until the socket identity and a fresh live attestation both
pass.
