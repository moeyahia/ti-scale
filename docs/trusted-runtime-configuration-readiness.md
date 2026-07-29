# Trusted runtime configuration readiness

## Purpose

`projectTrustedRuntimeConfigurationReadiness` is a source-only, read-only integrity projection for the three reviewed local documents required by a future Autonomous runtime composition:

- local Autonomous planning policy;
- runtime capability source manifests;
- engagement workspace mappings.

The projection does not discover configuration from environment variables or conventional filesystem locations. A caller must explicitly supply each `TrustedJsonFileReference`, including its trusted root and reviewed SHA-256. With no supplied references, the state remains `unconfigured` and no file is read.

## Status contract

The overall projection and each document use these states:

- `unconfigured` — no reference was supplied;
- `valid` — the file passed trusted-path, owner, permission, byte-digest, JSON-schema, and semantic validation;
- `invalid` — the configured reference, digest, document shape, or cross-references failed validation;
- `unavailable` — the configured file could not be read, or the complete three-document set is not available.

The overall projection is `valid` only when all three documents are configured and valid. A partial set is `unavailable`, even if each supplied document is individually valid.

## Information boundary

The projection returns only:

- status and public reason text;
- public schema and document version identifiers after successful validation;
- byte size;
- exact-source and canonical-value SHA-256 digests;
- the time of the read.

It never returns file paths, trust roots, raw operating-system errors, configuration bodies, tool arguments, target paths, provider bindings, credentials, or secrets. Invalid and unavailable documents receive fixed public explanations so filesystem errors cannot disclose local paths.

## Execution boundary

A valid projection proves configuration integrity only. It deliberately sets all of these values to `false`:

- `executionAuthorized`;
- `plannerMounted`;
- `providerExecutionMounted`;
- `specialistExecutionMounted`;
- `toolExecutionMounted`.

The projector does not construct a planner, provider, specialist, MCP client, tool transport, workspace resolver, or runtime composition. It does not mutate the database or runtime readiness and cannot make a mission executable. Production activation still requires the separate composition and live-attestation gates documented in [autonomous-local-runtime.md](./autonomous-local-runtime.md).

## Source usage

```ts
import {
  projectTrustedRuntimeConfigurationReadiness,
  type TrustedRuntimeConfigurationReferences,
} from "../server/trusted-runtime-config";

const references: TrustedRuntimeConfigurationReferences = {
  planningPolicy: reviewedPlanningPolicyReference,
  runtimeSourceManifests: reviewedManifestReference,
  workspaceMappings: reviewedWorkspaceMappingReference,
};

const readiness = projectTrustedRuntimeConfigurationReadiness(references);
```

Supplying references is an explicit deployment-composition decision. This module intentionally does not define environment-variable names, service mounts, credentials, or default host paths.

## Validation

Focused tests prove:

- default unconfigured behavior performs no configured file load;
- missing files are reported as unavailable without path leakage;
- malformed and digest-drifted files are invalid;
- partial configuration cannot become complete;
- all three real loaders must succeed for a valid projection;
- a valid result still grants no provider, specialist, planner, or tool authority.
