import type { IntakeActionClass } from "../../domain/types/intake";
import type { Journey } from "../../domain/types/commandOs";

export interface ActionCapabilityPresentation {
  readonly label: string;
  readonly explanation: string;
}

/** Keep missing implementation distinct from a temporarily unavailable path. */
export function actionCapabilityPresentation(
  action: IntakeActionClass,
  journey: Journey,
): ActionCapabilityPresentation {
  if (action.capability.availability === "unsupported") {
    return {
      label: "Not implemented",
      explanation: "No connected agent and tool binding implements this action class in the current runtime.",
    };
  }
  if (action.capability.availability === "unavailable") {
    return {
      label: "Temporarily unavailable",
      explanation: "The action class is implemented, but its assigned agent, tool, or dependency is not currently ready.",
    };
  }
  if (journey === "autonomous") {
    return action.capability.enforcementReady
      ? {
          label: "Autonomous-ready",
          explanation: "A reviewed local execution path can enforce this action class inside the signed Autonomous contract.",
        }
      : {
          label: "Guided path only",
          explanation: "Mapped tools are installed, but no reviewed Autonomous executor is authorized for this action class.",
        };
  }
  return {
    label: "Guided mapping available",
    explanation: "Mapped tools are installed; every consequential Guided action still requires one exact operator decision.",
  };
}
