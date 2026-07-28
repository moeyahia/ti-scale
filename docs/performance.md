# Performance

Ti-Scale measures performance against the built standalone application. A
successful source build is not treated as browser-performance proof.

## Bundle gate

Run:

```bash
bun run performance:bundle
```

The gate rebuilds the application, discovers the JavaScript requested by the
generated HTML shell, recomputes gzip sizes from the exact built bytes, and
enforces:

- initial JavaScript at or below 250 kB gzip;
- each lazily loaded route or worker chunk at or below 150 kB gzip.

The command exits non-zero on a regression and prints a machine-readable
measurement record. It does not retain an archive or copy of a prior build.

## Browser budgets

Run the browser gate with:

```bash
bun run performance:web-vitals
```

The command creates one invocation-owned production build under the disposable
E2E root, serves those exact bytes from a loopback standalone server, and
removes the build when the run ends. It does not publish a release or retain a
restorable application copy.

The gate records seven cold browser-context samples for each environment and
computes p75 with the documented nearest-rank method. The desktop and mobile
tests share one worker but are independent, so a desktop regression does not
prevent collection of the mobile result. Each sample:

- disables the browser cache;
- installs buffered observers before application code runs;
- enlarges the Resource Timing buffer to 10,000 entries and fails if it is
  exhausted;
- records FCP, LCP, Core Web Vitals CLS using the maximum session window,
  Event Timing, and long tasks at full precision;
- waits for the document, fonts, required API work, and a measured two-second
  LCP quiet interval before generating input;
- opens the Command Palette and closes it with Escape to measure a synthetic
  command-palette INP;
- retains the actual navigation document and all static responses observed by
  the BrowserContext—including dedicated-worker traffic—then hashes their
  bodies after metric capture so integrity work does not alter the measured
  critical path;
- classifies every observed URL against the complete build manifest: exact
  regular files—including public-root logos, brand media, fonts, manifests,
  workers, and models—are verified, `/api/v2` and non-HTTP traffic is recorded
  as an explicit exclusion, and unknown same-origin paths or any unpinned
  external HTTP(S) resource fail the gate.

Desktop uses a 1440×900 Chromium context. The mid-tier mobile profile uses a
390×844 touch context, 4× CPU throttling, 150 ms latency, 1.6 Mbit/s download,
and 750 Kbit/s upload. Chromium's Event Timing API has a 16 ms reporting floor;
when the represented interaction produces no entry above that floor, the gate
records a conservative 16 ms INP instead of an unsupported zero.

Before the managed build starts, the runner creates a canonical SHA-256
manifest of every tracked and non-ignored untracked regular source file.
Source symlinks fail closed because Vite would dereference bytes outside that
manifest. Managed performance builds disable ambient Vite env-file loading and
inherit only the reviewed E2E child environment, so ignored `.env` content is
neither a hidden build input nor a secret-derived evidence commitment. Each
browser result recomputes the source manifest after sampling and fails on
drift. The runner repeats the check when Playwright exits, so a late edit also
fails the invocation.

Immediately before sampling, the test hashes every regular file in the
invocation-owned build directory. It hashes that complete tree again after
sampling, rejects drift, and verifies every retained document/static response
body against both the pre-sampling and post-sampling build. Request identity
retains query parameters while only a safely decoded, traversal-free pathname
is used for exact manifest lookup. One immutable build baseline is shared by
desktop, mobile, and the dedicated-worker coverage proof, preventing two
environments from passing against different builds. Evidence also records
every dynamic and non-HTTP exclusion plus rejected external-resource attempts,
the Chromium version, Node and Bun
runtimes, operating-system release, architecture, processor model/count, and
total memory. These provenance records identify the measured bytes; they do
not promote them into a release candidate.

The enforced p75 budgets are:

| Environment | FCP | LCP | INP | CLS |
| --- | ---: | ---: | ---: | ---: |
| Desktop | ≤ 1.0 s | ≤ 1.8 s | ≤ 150 ms | ≤ 0.05 |
| Mid-tier mobile | ≤ 1.5 s | ≤ 2.5 s | ≤ 200 ms | ≤ 0.05 |

Before Playwright starts, the launcher atomically reserves
`test-results/performance/<run-id>/`. Reusing a run ID fails before reporters
can truncate prior JSON, HTML, traces, or screenshots. All Playwright and
per-environment Web Vitals records stay inside that immutable run directory.
The records explicitly remain ineligible for
release attestation until the exact source and build are immutable and the
separate interaction, visual, accessibility, soak, preview-acceptance, and
human-signoff gates pass.

Evidence publication uses one same-directory temporary inode, flushes it, and
links it into place with no-overwrite semantics before immediately removing
the temporary name. This is atomic publication, not a retained backup or
restorable application copy.
