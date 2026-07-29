# API

## Contract

Ti-Scale exposes a versioned JSON API under `/api/v2`.

The running server publishes the authoritative endpoint catalog and event schema:

```text
GET /api/v2/openapi.json
GET /api/v2/contracts/events
```

Use those documents rather than copying endpoint lists into client code.

## Authentication

Create a browser session by exchanging the configured operator token:

```bash
curl -i \
  -H 'Content-Type: application/json' \
  -d "{\"operatorToken\":\"$TI_SCALE_OPERATOR_TOKEN\"}" \
  http://127.0.0.1:3132/api/v2/auth/session
```

The response sets a signed, time-limited HTTP-only session cookie and a CSRF cookie. Cookie-authenticated mutations must echo the CSRF value in the published CSRF request header.

Non-browser clients may use:

```http
Authorization: Bearer <operator-token>
```

An explicitly supplied invalid bearer header fails closed; the server does not fall back to a browser cookie.

## Request conventions

- Send JSON as `application/json; charset=utf-8`.
- Request bodies are bounded; the default server rejects oversized JSON.
- Supply `X-Request-ID` with a safe correlation identifier or use the generated response value.
- Use `Idempotency-Key` on mutations marked idempotent in the published contract.
- Use optimistic record versions where a resource supports concurrent edits.
- Treat IDs as opaque stable strings.

## Error envelope

Errors use one shape:

```json
{
  "error": {
    "code": "machine_readable_code",
    "message": "Technical summary",
    "humanMessage": "Operator-readable explanation",
    "retryable": false,
    "category": "dependency_missing",
    "details": {},
    "traceId": "request-correlation-id",
    "remediation": "Specific next action",
    "timestamp": "2026-07-18T00:00:00.000Z"
  }
}
```

Do not retry solely because a response is non-successful. Honor `retryable`, category, and remediation.

## Resource families

| Prefix | Purpose |
| --- | --- |
| `/api/v2/overview` | Command Center projection |
| `/api/v2/registries` | Runtime-derived intake data |
| `/api/v2/missions` | Mission portfolio, contracts, and branches |
| `/api/v2/runs` | Canonical run, plan, and checkpoint views |
| `/api/v2/guided` and `/api/v2/guided-decisions` | Guided transcript and exact-step decisions |
| `/api/v2/events` | SSE stream, replay, and gap repair |
| `/api/v2/intelligence` | Evidence, findings, and artifacts |
| `/api/v2/operational-truth` | Logs, observations, candidates, verified evidence, and diagnoses |
| `/api/v2/operations` | Actions, recovery, and follow-up runs |
| `/api/v2/brain` | Memory, Context Packs, control policy, and vault |
| `/api/v2/learning` | Evaluations and reusable lessons |
| `/api/v2/research` | Bounded research campaigns and promotion state |
| `/api/v2/observability` | Events, traces, logs, health, and audit exports |
| `/api/v2/system` | Readiness, providers, tools, policies, and health |

## Capability truth

Several domain endpoints record verified results without initiating network or tool activity:

- Page-capture routes store supplied capture metadata and provenance; they do not launch a browser capture.
- CVE routes store evidence-gated applicability and source provenance; they do not imply a live upstream lookup.
- Script-artifact routes version documented source; they do not execute scripts.
- Research routes manage bounded campaign state and evaluation policy; an external proposal or experiment runner is not attached by default.

Execution-dependent Guided and run-control endpoints return a diagnosable `503` when the production runtime adapter is absent. Clients must display the provided explanation and remediation rather than treating it as an unknown failure.

## Pagination and filtering

Search endpoints use server-side filters and bounded pages. Event replay uses an opaque cursor. Clients must preserve returned cursors and must not construct them manually.

## Example readiness request

```bash
curl -sS http://127.0.0.1:3132/api/v2/system/readiness | jq
```

Readiness is journey-specific. Do not infer Autonomous capability from a successful health response.
