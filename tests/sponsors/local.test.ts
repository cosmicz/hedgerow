// The in-process fallbacks always run; they define the behaviour the sponsor
// backends must match.
import { LocalActionProjection } from "../../src/adapters/sponsors/local/action-projection.js";
import { LocalObservationStore } from "../../src/adapters/sponsors/local/observation-store.js";
import { actionProjectionContract } from "./action-projection.contract.js";
import { observationStoreContract } from "./observation-store.contract.js";

observationStoreContract("local", () => new LocalObservationStore());
actionProjectionContract("local", () => new LocalActionProjection());
