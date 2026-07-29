import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();
const dropInPath = join(
  root,
  "deployment/systemd/ti-scale.service.d/30-openrouter-guided.conf",
);

describe("OpenRouter production deployment contract", () => {
  test("uses a systemd credential mount and one exact pinned model without embedding a key", () => {
    const dropIn = readFileSync(dropInPath, "utf8");
    expect(dropIn).toContain(
      "LoadCredential=openrouter-api-key:/etc/ti-scale/openrouter-api-key",
    );
    expect(dropIn).toContain("Environment=TI_SCALE_OPENROUTER_GUIDED_ENABLED=true");
    expect(dropIn).toContain(
      "Environment=TI_SCALE_OPENROUTER_CREDENTIAL_PATH=%d/openrouter-api-key",
    );
    expect(dropIn).toContain("Environment=TI_SCALE_OPENROUTER_MODEL=openai/gpt-5.2");
    expect(dropIn).not.toMatch(/^Environment=(?:OPENROUTER_API_KEY|.*(?:TOKEN|SECRET))=/m);
    expect(dropIn).not.toMatch(/sk-or-/u);
  });

  test("keeps the checked-in example disabled and the Vault root scoped to a parent sandbox", () => {
    const example = readFileSync(join(root, ".env.example"), "utf8");
    expect(example).toContain("TI_SCALE_OPENROUTER_GUIDED_ENABLED=false");
    expect(example).toContain("# TI_SCALE_VAULT_ROOT=/var/lib/ti-scale/vaults");
    expect(example).not.toContain("TI_SCALE_VAULT_ROOT=/var/lib/ti-scale/Ti-Scale-Brain");
  });
});
