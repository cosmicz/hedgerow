// Must not fire: classifiers import only judgment types.
import type { Judgment } from "../domain/judgment";

export function abstain(): Judgment["category"] {
  return "unknown";
}
