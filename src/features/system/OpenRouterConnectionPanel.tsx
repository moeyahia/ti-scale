import { useEffect, useState, type FormEvent } from "react";
import {
  fetchOpenRouterConnection,
  refreshOpenRouterAttestation,
  updateOpenRouterConnection,
} from "../../data/api/providerConnections";
import { useQuery, useQueryCache } from "../../data/cache/QueryProvider";
import {
  Button,
  Card,
  ErrorPanel,
  LoadingPanel,
  StatusPill,
} from "../../design-system/components/Primitives";
import { TitaniumSelect } from "../../design-system/components/TitaniumSelect";
import { formatTime, KeyValueGrid } from "../runs/OperationalSurface";
import "./provider-connections.css";

const QUERY_KEY = "provider-connection:openrouter";

export function OpenRouterConnectionPanel() {
  const cache = useQueryCache();
  const connection = useQuery(
    QUERY_KEY,
    fetchOpenRouterConnection,
    { staleTime: 5_000 },
  );
  const [hydratedVersion, setHydratedVersion] = useState<string>();
  const [enabled, setEnabled] = useState(false);
  const [model, setModel] = useState("openai/gpt-5.2");
  const [credential, setCredential] = useState("");
  const [saving, setSaving] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [message, setMessage] = useState("");
  const [mutationError, setMutationError] = useState<Error>();

  const record = connection.data;
  const hydrationKey = record
    ? `${record.configuration.version}:${record.configuration.enabled}:${record.configuration.model}`
    : undefined;
  useEffect(() => {
    if (!record || !hydrationKey || hydratedVersion === hydrationKey) return;
    setEnabled(record.configuration.enabled);
    setModel(record.configuration.model);
    setCredential("");
    setMessage("");
    setMutationError(undefined);
    setHydratedVersion(hydrationKey);
  }, [hydratedVersion, hydrationKey, record]);

  const canonicalCredentialCanBeKept = Boolean(
    record?.configuration.source === "canonical_provider_config"
    && record.configuration.credentialConfigured,
  );
  const modelValid = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$/u
    .test(model.trim());
  const credentialValid = credential.length >= 20
    && credential.length <= 4_096
    && !/[\s\u0000-\u001F\u007F]/u.test(credential);
  const changed = Boolean(record && (
    enabled !== record.configuration.enabled
    || model.trim() !== record.configuration.model
    || credential.length > 0
    || record.configuration.source !== "canonical_provider_config"
  ));
  const canSave = Boolean(
    record
    && modelValid
    && changed
    && (!enabled || canonicalCredentialCanBeKept || credentialValid)
    && !saving
    && !refreshing,
  );
  const canRefresh = Boolean(
    record
    && record.configuration.enabled
    && record.configuration.version > 0
    && !record.activation.restartRequired
    && !saving
    && !refreshing,
  );

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!record || !canSave) return;
    setSaving(true);
    setMutationError(undefined);
    setMessage("");
    try {
      const result = await updateOpenRouterConnection(enabled
        ? {
            enabled: true,
            model: model.trim(),
            credential: credential
              ? { action: "replace", value: credential }
              : { action: "keep" },
            expectedVersion: record.configuration.version,
          }
        : {
            enabled: false,
            model: model.trim(),
            credential: { action: "remove" },
            expectedVersion: record.configuration.version,
          });
      setCredential("");
      setHydratedVersion("");
      await connection.reconcile();
      setMessage(result.activation.humanMessage);
    } catch (error) {
      setCredential("");
      setMutationError(error instanceof Error
        ? error
        : new Error("The OpenRouter connection could not be saved"));
    } finally {
      setSaving(false);
    }
  };

  const refresh = async () => {
    if (!record || !canRefresh) return;
    setRefreshing(true);
    setMutationError(undefined);
    setMessage("");
    try {
      const result = await refreshOpenRouterAttestation(
        record.configuration.version,
      );
      cache.invalidate("model-catalog");
      setHydratedVersion("");
      await connection.reconcile();
      setMessage(result.connection.activation.humanMessage);
    } catch (error) {
      setMutationError(error instanceof Error
        ? error
        : new Error("The OpenRouter verification could not be completed"));
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <Card
      id="openrouter-connection"
      className="provider-connection"
      aria-label="OpenRouter provider connection"
    >
      <div className="os-card-heading">
        <div>
          <p className="os-eyebrow">Public planning provider</p>
          <h2>OpenRouter connection</h2>
          <p>
            Configure one private service-owned key and exact model for
            sanitized Guided planning, explanations, critique, and reporting.
          </p>
        </div>
        <StatusPill status={record?.activation.status ?? "loading"}>
          {record?.activation.status.replaceAll("_", " ") ?? "Loading"}
        </StatusPill>
      </div>

      {connection.isLoading && (
        <LoadingPanel label="Loading the private OpenRouter connection record" />
      )}
      {connection.error && !record && (
        <ErrorPanel
          title="OpenRouter connection is unavailable"
          error={connection.error}
          onRetry={connection.refresh}
        />
      )}

      {record && (
        <>
          <p className="provider-connection__boundary">
            {record.activation.humanMessage}
          </p>
          <KeyValueGrid items={[
            {
              label: "Credential",
              value: record.configuration.credentialConfigured
                ? "Stored privately by the service"
                : "Not configured",
            },
            { label: "Exact model", value: record.configuration.model },
            {
              label: "Runtime check",
              value: `${record.runtime.status} · ${formatTime(record.runtime.lastCheckedAt)}`,
            },
            {
              label: "Specialist coverage",
              value: `${record.planningCompatibility.compatibleAgentIds.length} canonical agents · advisor only`,
            },
            {
              label: "Execution authority",
              value: "Remains with local policy-gated adapters",
            },
            {
              label: "Configuration version",
              value: record.configuration.version || "Not saved",
            },
          ]} />

          <form className="provider-connection__form" onSubmit={save}>
            <label>
              <span>Connection state</span>
              <TitaniumSelect
                data-control-id="openrouter-connection-state"
                aria-label="OpenRouter connection state"
                value={enabled ? "enabled" : "disabled"}
                disabled={saving || refreshing}
                onChange={(event) => {
                  const next = event.target.value === "enabled";
                  setEnabled(next);
                  if (!next) setCredential("");
                  setMessage("");
                  setMutationError(undefined);
                }}
              >
                <option value="enabled">Enabled for advisory planning</option>
                <option value="disabled">Disabled and remove credential</option>
              </TitaniumSelect>
            </label>

            <label>
              <span>Exact OpenRouter model</span>
              <input
                data-control-id="openrouter-model-id"
                aria-label="Exact OpenRouter model"
                value={model}
                disabled={saving || refreshing}
                inputMode="text"
                spellCheck={false}
                placeholder="openai/gpt-5.2"
                onChange={(event) => {
                  setModel(event.target.value);
                  setMessage("");
                  setMutationError(undefined);
                }}
              />
              <small>Use the provider/model identifier. Startup verifies this exact model before it enters the catalog.</small>
            </label>

            {enabled && (
              <label>
                <span>
                  {canonicalCredentialCanBeKept
                    ? "Replace credential (optional)"
                    : "OpenRouter credential"}
                </span>
                <input
                  data-control-id="openrouter-credential"
                  aria-label={canonicalCredentialCanBeKept
                    ? "Replace OpenRouter credential"
                    : "OpenRouter credential"}
                  type="password"
                  value={credential}
                  disabled={saving || refreshing}
                  autoComplete="off"
                  spellCheck={false}
                  data-1p-ignore="true"
                  data-lpignore="true"
                  placeholder={canonicalCredentialCanBeKept
                    ? "Leave empty to keep the service-owned key"
                    : "Paste completion key"}
                  onChange={(event) => {
                    setCredential(event.target.value);
                    setMessage("");
                    setMutationError(undefined);
                  }}
                />
                <small>The key is sent once over the authenticated same-origin session. It is never returned, audited, logged, or saved in browser storage.</small>
              </label>
            )}

            <div className="provider-connection__actions">
              <Button
                type="submit"
                data-control-id="openrouter-save-connection"
                disabled={!canSave}
              >
                {saving ? "Saving private connection" : "Save connection"}
              </Button>
              <Button
                type="button"
                variant="secondary"
                data-control-id="openrouter-refresh-attestation"
                disabled={!canRefresh}
                onClick={refresh}
              >
                {refreshing
                  ? "Verifying provider and model"
                  : "Verify connection & refresh catalog"}
              </Button>
            </div>
          </form>

          {record.activation.restartRequired && (
            <div className="provider-connection__restart" role="status">
              <strong>Restart required</strong>
              <p>
                The running process keeps its startup credential snapshot.
                Restart Ti-Scale to activate version {record.configuration.version};
                startup then performs the bounded provider and model attestation.
              </p>
            </div>
          )}
          {record.runtime.failureCode && !record.activation.restartRequired && (
            <div className="provider-connection__restart" role="alert">
              <strong>{record.runtime.failureCode.replaceAll("_", " ")}</strong>
              <p>{record.runtime.reason}</p>
              {record.runtime.remediation && <p>{record.runtime.remediation}</p>}
            </div>
          )}
          {mutationError && (
            <ErrorPanel
              title="OpenRouter connection change was not applied"
              error={mutationError}
              onRetry={connection.refresh}
            />
          )}
          {message && (
            <p className="provider-connection__message" role="status" aria-live="polite">
              {message}
            </p>
          )}
          <p className="provider-connection__compatibility">
            {record.planningCompatibility.explanation}
          </p>
        </>
      )}
    </Card>
  );
}
