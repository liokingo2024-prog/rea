import { ArtifactOperationError } from "./artifactOperationError.js";
import type { AnalysisErrorOptions } from "./analysisErrorBase.js";

/** Public mutation workflows that can retain this failure. */
export const ARTIFACT_PATCH_OPERATIONS = [
  "plan_artifact_patch",
  "apply_artifact_patch",
  "verify_artifact_patch",
] as const;

export type ArtifactPatchOperation = (typeof ARTIFACT_PATCH_OPERATIONS)[number];

/**
 * Why a planned or applied byte mutation was refused. These reasons are
 * separate from the read-side artifact reasons because a caller has to know
 * whether the selection, the artifact bytes, the container framing, the
 * requested authority or the post-write verification refused the change.
 */
export type ArtifactPatchReason = Extract<
  ArtifactOperationError["reason"],
  | "cancelled"
  | "format"
  | "integrity"
  | "limit"
  | "path"
  | "unavailable"
  | "io"
  | "invalid_input"
  | "expected_bytes_mismatch"
  | "match_unresolved"
  | "overlap"
  | "container_unsupported"
  | "authority_required"
  | "verification_failed"
>;

/**
 * Typed refusal or failure of one caller-directed artifact mutation. The
 * artifact path and the retained detail identify exactly which selection,
 * span, container rule or authority precondition refused, so a caller can
 * tell whether anything was written.
 */
export class ArtifactPatchError extends ArtifactOperationError {
  override readonly userMessage: string;

  constructor(
    operation: ArtifactPatchOperation,
    reason: ArtifactPatchReason,
    readonly artifactPath: string,
    detail: string,
    options?: AnalysisErrorOptions,
  ) {
    super(operation, reason, undefined, `${artifactPath}: ${detail}`, options);
    this.userMessage = detail;
  }
}
