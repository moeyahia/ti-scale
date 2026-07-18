import { useId, useState } from "react";
import { Button } from "../../design-system/components/Primitives";
import { ContextPackPanel } from "./ContextPackPanel";

export function ContextUsedDisclosure({ packId }: { packId: string }) {
  const [open, setOpen] = useState(false);
  const disclosureId = `context-used-${useId().replaceAll(":", "")}`;
  return (
    <div className="os-context-used-disclosure">
      <Button
        type="button"
        variant="quiet"
        aria-expanded={open}
        aria-controls={disclosureId}
        onClick={() => setOpen((value) => !value)}
      >
        {open ? "Hide context used" : "Context used"}
      </Button>
      {open && <div id={disclosureId}><ContextPackPanel packId={packId} /></div>}
    </div>
  );
}
