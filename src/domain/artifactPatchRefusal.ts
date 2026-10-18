import type { ArtifactPatchReason } from "./artifactPatchError.js";
import { err, type Result } from "./result.js";

/** A refused mutation plus the exact rule that refused it. */
export interface ArtifactPatchRefusal {
  readonly reason: ArtifactPatchReason;
  readonly detail: string;
}

/** Build a refusal result for one exact rule violation. */
export const refuseArtifactPatch = (
  reason: ArtifactPatchReason,
  detail: string,
): Result<never, ArtifactPatchRefusal> => err({ reason, detail });
