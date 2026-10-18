import { createHash } from "node:crypto";
import { isAbsolute, resolve } from "node:path";

import { z } from "zod";

import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import {
  AnalysisAccessDeniedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  ARTIFACT_PATCH_LIMITS,
  applyArtifactPatchInputSchema,
  artifactPatchApplyResultSchema,
  artifactPatchPlanSchema,
  artifactPatchVerifyResultSchema,
  planArtifactPatchInputSchema,
  verifyArtifactPatchInputSchema,
  type ApplyArtifactPatchInput,
  type ArtifactPatchApplyResult,
  type ArtifactPatchPlan,
  type ArtifactPatchVerifyResult,
  type PlanArtifactPatchInput,
  type VerifyArtifactPatchInput,
} from "../domain/artifactPatch.js";
import {
  ArtifactPatchError,
  type ArtifactPatchOperation,
} from "../domain/artifactPatchError.js";
import {
  classifyArtifactContainer,
  containerFramingLimitations,
  verifyContainerIntegrity,
  type ArtifactContainer,
} from "../domain/artifactPatchContainer.js";
import {
  parseHexBytes,
  planArtifactPatch as computeArtifactPatchPlan,
  previewHex,
  verifyArtifactPatchRegions,
  type ComputedArtifactPatchPlan,
  type PatchChange,
} from "../domain/artifactPatchPlan.js";
import type { ArtifactPatchRefusal } from "../domain/artifactPatchRefusal.js";
import { createEvidence, type Evidence } from "../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  NonRegularFileReadError,
  RegularFileChangedError,
} from "../filesystem/RegularFile.js";
import { readBoundedFileBytes } from "../process/BoundedFileBytes.js";
import type { ExecutionOptions } from "./AnalysisProvider.js";
import { ARTIFACT_PATCH_PROVIDER as PROVIDER } from "./InvestigationProviders.js";
import { withRegularFile } from "./RegularFileRead.js";
import {
  RegularFileReplacementChangedError,
  RegularFileWriteExistsError,
  RegularFileWriteTargetError,
  replaceRegularFileBytesInPlace,
  writeRegularFileBytes,
} from "./RegularFileWrite.js";

const PLAN_OPERATION: ArtifactPatchOperation = "plan_artifact_patch";
const APPLY_OPERATION: ArtifactPatchOperation = "apply_artifact_patch";
const VERIFY_OPERATION: ArtifactPatchOperation = "verify_artifact_patch";

/** Artifact bytes exceeded the whole-file admission bound. */
class ArtifactByteLimitError extends Error {
  constructor(
    readonly path: string,
    readonly bytes: bigint,
  ) {
    super(
      `Artifact is ${bytes} bytes, beyond the ${ARTIFACT_PATCH_LIMITS.artifactBytes}-byte whole-file admission bound`,
    );
    this.name = "ArtifactByteLimitError";
  }
}

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const errorMessage = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const errorCode = (cause: unknown): string =>
  cause instanceof Error && "code" in cause ? String(cause.code) : "";

/** Plan a mutation over an admitted artifact without writing anything. */
export const planArtifactPatch = async (
  rawInput: unknown,
  resources: ArtifactResourceScope,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const parsed = planArtifactPatchInputSchema.safeParse(rawInput);
  return parsed.success
    ? planArtifactPatchValidated(parsed.data, resources, options)
    : err(
        analysisInputErrorFromIssues(
          PLAN_OPERATION,
          parsed.error.issues,
          rawInput,
        ),
      );
};

/** Plan a mutation whose input was already parsed by a named adapter contract. */
export const planArtifactPatchValidated = async (
  input: PlanArtifactPatchInput,
  resources: ArtifactResourceScope,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  if (!isAbsolute(input.target_path))
    return err(absolutePathError(PLAN_OPERATION, input.target_path));
  try {
    options.signal?.throwIfAborted();
    const read = await readArtifact(
      input.target_path,
      resources,
      options.signal,
      PLAN_OPERATION,
    );
    if (!read.ok) return read;
    const plan = buildPlan(PLAN_OPERATION, input, read.value);
    if (!plan.ok) return plan;
    return ok(planEvidence(plan.value, input.target_path));
  } catch (cause: unknown) {
    return err(
      mapFailure(cause, PLAN_OPERATION, input.target_path, options.signal),
    );
  }
};

/** Apply a planned mutation to a copy, or in place under explicit authority. */
export const applyArtifactPatch = async (
  rawInput: unknown,
  resources: ArtifactResourceScope,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const parsed = applyArtifactPatchInputSchema.safeParse(rawInput);
  return parsed.success
    ? applyArtifactPatchValidated(parsed.data, resources, options)
    : err(
        analysisInputErrorFromIssues(
          APPLY_OPERATION,
          parsed.error.issues,
          rawInput,
        ),
      );
};

/** Apply a mutation whose input was already parsed by a named adapter contract. */
export const applyArtifactPatchValidated = async (
  input: ApplyArtifactPatchInput,
  resources: ArtifactResourceScope,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  if (!isAbsolute(input.target_path))
    return err(absolutePathError(APPLY_OPERATION, input.target_path));
  const authority = validateAuthority(input);
  if (!authority.ok) return authority;
  const destination = authority.value;
  try {
    options.signal?.throwIfAborted();
    const read = await readArtifact(
      input.target_path,
      resources,
      options.signal,
      APPLY_OPERATION,
    );
    if (!read.ok) return read;
    if (
      destination.kind === "in_place" &&
      destination.expectedTargetSha256 !== read.value.sha256
    )
      return err(
        new ArtifactPatchError(
          APPLY_OPERATION,
          "authority_required",
          input.target_path,
          `the target sha256 is ${read.value.sha256}, not the authorized ${destination.expectedTargetSha256}; the artifact changed since authorization`,
        ),
      );
    const computed = computeArtifactPatchPlan(read.value.bytes, {
      targetSha256: read.value.sha256,
      operations: input.operations,
    });
    if (!computed.ok)
      return err(
        new ArtifactPatchError(
          APPLY_OPERATION,
          computed.error.reason,
          input.target_path,
          computed.error.detail,
        ),
      );
    if (
      input.plan_digest !== undefined &&
      input.plan_digest !== computed.value.planDigest
    )
      return err(
        new ArtifactPatchError(
          APPLY_OPERATION,
          "invalid_input",
          input.target_path,
          `the artifact and operations produce plan ${computed.value.planDigest}, not the supplied ${input.plan_digest}; re-plan before applying`,
        ),
      );
    const plan = buildPlan(APPLY_OPERATION, input, read.value, computed.value);
    if (!plan.ok) return plan;
    options.signal?.throwIfAborted();
    const written =
      destination.kind === "in_place"
        ? await replaceRegularFileBytesInPlace(
            computed.value.patchedBytes,
            input.target_path,
            destination.expectedTargetSha256,
            ARTIFACT_PATCH_LIMITS.artifactBytes,
            options.signal,
          )
        : await writeRegularFileBytes(
            computed.value.patchedBytes,
            destination.outputPath,
            input.overwrite,
            options.signal,
          );
    const verification = await verifyWrittenArtifact(
      written.path,
      plan.value,
      resources,
      options.signal,
      APPLY_OPERATION,
    );
    if (!verification.ok) return verification;
    const result = artifactPatchApplyResultSchema.parse({
      plan_digest: plan.value.plan_digest,
      mode: destination.kind,
      target: plan.value.target,
      artifact: {
        path: written.path,
        sha256: verification.value.sha256,
        bytes: verification.value.bytes,
      },
      operations_applied: plan.value.operations.length,
      changes_applied: plan.value.changes.length,
      container: plan.value.container,
      verification: {
        state: "verified",
        regions_verified: plan.value.operations.length,
        expected_sha256: plan.value.resulting.sha256,
      },
      limitations: [
        ...plan.value.limitations,
        destination.kind === "in_place"
          ? "The target artifact was replaced in place after its authorized digest was re-read and its descriptor identity re-checked. No backup copy was retained."
          : "The selected target artifact was left unchanged; the patched artifact is the reported output copy.",
      ],
    });
    return ok(applyEvidence(result, input.target_path, written));
  } catch (cause: unknown) {
    return err(
      mapFailure(cause, APPLY_OPERATION, input.target_path, options.signal),
    );
  }
};

/** Re-check a written artifact against an expected digest and byte regions. */
export const verifyArtifactPatch = async (
  rawInput: unknown,
  resources: ArtifactResourceScope,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const parsed = verifyArtifactPatchInputSchema.safeParse(rawInput);
  return parsed.success
    ? verifyArtifactPatchValidated(parsed.data, resources, options)
    : err(
        analysisInputErrorFromIssues(
          VERIFY_OPERATION,
          parsed.error.issues,
          rawInput,
        ),
      );
};

/** Re-check an artifact whose input was already parsed by a named adapter contract. */
export const verifyArtifactPatchValidated = async (
  input: VerifyArtifactPatchInput,
  resources: ArtifactResourceScope,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  if (!isAbsolute(input.target_path))
    return err(absolutePathError(VERIFY_OPERATION, input.target_path));
  try {
    options.signal?.throwIfAborted();
    const read = await readArtifact(
      input.target_path,
      resources,
      options.signal,
      VERIFY_OPERATION,
    );
    if (!read.ok) return read;
    const container = classifyArtifactContainer(read.value.bytes);
    if (!container.ok)
      return err(
        new ArtifactPatchError(
          VERIFY_OPERATION,
          container.error.reason,
          input.target_path,
          container.error.detail,
        ),
      );
    const integrity = verifyContainerIntegrity(
      read.value.bytes,
      container.value,
    );
    const checked = verifyArtifactPatchRegions(
      read.value.bytes,
      input.regions.map(({ file_offset, expected_hex }) => ({
        fileOffset: file_offset,
        expected: parseHexBytes(expected_hex),
      })),
    );
    const result = artifactPatchVerifyResultSchema.parse({
      target: {
        path: input.target_path,
        sha256: read.value.sha256,
        bytes: read.value.bytes.length,
      },
      digest: {
        state:
          input.expected_sha256 === undefined
            ? "not_requested"
            : input.expected_sha256 === read.value.sha256
              ? "matches"
              : "mismatch",
        expected_sha256: input.expected_sha256 ?? null,
        actual_sha256: read.value.sha256,
      },
      regions: checked.map((region) => ({
        file_offset: region.fileOffset,
        expected_hex: region.expected.toString("hex"),
        actual_hex: region.actual.toString("hex"),
        state: region.actual.equals(region.expected) ? "matches" : "mismatch",
      })),
      container: {
        kind: container.value.kind,
        integrity: integrity.state,
        entries_checked: integrity.entriesChecked,
        limitations: containerLimitations(container.value),
      },
      limitations: [
        ...containerFramingLimitations(container.value),
        ...(integrity.detail === null ? [] : [integrity.detail]),
      ],
    });
    return ok(verifyEvidence(result, input.target_path));
  } catch (cause: unknown) {
    return err(
      mapFailure(cause, VERIFY_OPERATION, input.target_path, options.signal),
    );
  }
};

interface ReadArtifact {
  readonly bytes: Buffer;
  readonly sha256: string;
}

const readArtifact = async (
  path: string,
  resources: ArtifactResourceScope,
  signal: AbortSignal | undefined,
  operation: ArtifactPatchOperation,
): Promise<Result<ReadArtifact, AnalysisError>> => {
  try {
    const bytes = await withRegularFile(
      path,
      async (handle, stats) => {
        if (stats.size > ARTIFACT_PATCH_LIMITS.artifactBytes)
          throw new ArtifactByteLimitError(path, BigInt(stats.size));
        const read = await readBoundedFileBytes(handle, stats.size, signal);
        if (read === undefined || read.length !== stats.size)
          throw new RegularFileChangedError(path);
        return read;
      },
      {
        symlinks: "reject",
        ...(signal === undefined ? {} : { signal }),
        resources,
      },
    );
    return ok({ bytes, sha256: sha256(bytes) });
  } catch (cause: unknown) {
    return err(mapFailure(cause, operation, path, signal));
  }
};

const absolutePathError = (
  operation: ArtifactPatchOperation,
  path: string,
): AnalysisInputError =>
  new AnalysisInputError(operation, undefined, [
    {
      path: ["target_path"],
      reason: "invalid_format",
      message: `Artifact paths must be absolute filesystem paths on this host: ${path}`,
    },
  ]);

type Destination =
  | { readonly kind: "copy"; readonly outputPath: string }
  | { readonly kind: "in_place"; readonly expectedTargetSha256: string };

const authorityRefusal = (
  input: ApplyArtifactPatchInput,
  detail: string,
): Result<never, ArtifactPatchError> =>
  err(
    new ArtifactPatchError(
      APPLY_OPERATION,
      "authority_required",
      input.target_path,
      detail,
    ),
  );

const invalidCombination = (
  input: ApplyArtifactPatchInput,
  path: string,
  detail: string,
): Result<never, ArtifactPatchError> =>
  err(
    new ArtifactPatchError(
      APPLY_OPERATION,
      "invalid_input",
      input.target_path,
      detail,
      {
        diagnostics: { combination_field: path },
      },
    ),
  );

const validateAuthority = (
  input: ApplyArtifactPatchInput,
): Result<Destination, ArtifactPatchError> => {
  if (!input.in_place) {
    if (input.output_path === undefined)
      return invalidCombination(
        input,
        "output_path",
        "output_path is required unless in_place is true",
      );
    if (!isAbsolute(input.output_path))
      return invalidCombination(
        input,
        "output_path",
        `output_path must be absolute: ${input.output_path}`,
      );
    if (input.acknowledge_in_place)
      return invalidCombination(
        input,
        "acknowledge_in_place",
        "acknowledge_in_place is only accepted together with in_place",
      );
    if (input.expected_target_sha256 !== undefined)
      return invalidCombination(
        input,
        "expected_target_sha256",
        "expected_target_sha256 is only accepted together with in_place",
      );
    if (resolve(input.output_path) === resolve(input.target_path))
      return invalidCombination(
        input,
        "output_path",
        "output_path must differ from target_path; use in_place with acknowledgements to replace the target itself",
      );
    return ok({ kind: "copy", outputPath: input.output_path });
  }
  if (!input.acknowledge_in_place)
    return authorityRefusal(
      input,
      "in_place replaces the caller's artifact irreversibly and requires acknowledge_in_place: true",
    );
  if (input.expected_target_sha256 === undefined)
    return authorityRefusal(
      input,
      "in_place requires expected_target_sha256, so the replacement is bound to the exact artifact bytes the caller authorized",
    );
  if (input.output_path !== undefined)
    return invalidCombination(
      input,
      "output_path",
      "output_path is not accepted with in_place",
    );
  return ok({
    kind: "in_place",
    expectedTargetSha256: input.expected_target_sha256,
  });
};

const containerSummary = (container: ArtifactContainer) => ({
  kind: container.kind,
  entries:
    container.kind === "zip"
      ? container.members.length
      : container.kind === "asar"
        ? container.files.length
        : null,
  limitations: containerLimitations(container),
});

const containerLimitations = (container: ArtifactContainer): string[] =>
  container.kind === "asar" && container.unmodeledEntries.length > 0
    ? [
        `${container.unmodeledEntries.length} ASAR entry or entries are unpacked files, links or unrecognized nodes; they occupy no modeled data ranges and are not patchable.`,
      ]
    : [];

const changeSummary = (change: PatchChange) => {
  const before = previewHex(change.before);
  const after = previewHex(change.after);
  return {
    kind: change.kind,
    container_entry: change.containerEntry,
    field: change.field,
    offset: change.offset,
    bytes: change.after.length,
    before_hex: before.hex,
    after_hex: after.hex,
  };
};

const buildPlan = (
  operation: ArtifactPatchOperation,
  input: PlanArtifactPatchInput | ApplyArtifactPatchInput,
  read: ReadArtifact,
  computedInput?: ComputedArtifactPatchPlan,
): Result<ArtifactPatchPlan, AnalysisError> => {
  const computed: Result<ComputedArtifactPatchPlan, ArtifactPatchRefusal> =
    computedInput === undefined
      ? computeArtifactPatchPlan(read.bytes, {
          targetSha256: read.sha256,
          operations: input.operations,
        })
      : ok(computedInput);
  if (!computed.ok)
    return err(
      new ArtifactPatchError(
        operation,
        computed.error.reason,
        input.target_path,
        computed.error.detail,
      ),
    );
  const byteRangeChanges = computed.value.changes.filter(
    (change) => change.kind === "byte_range",
  );
  const plan = artifactPatchPlanSchema.parse({
    target: {
      path: input.target_path,
      sha256: read.sha256,
      bytes: read.bytes.length,
    },
    container: containerSummary(computed.value.container),
    operations: computed.value.operations.map((operation) => {
      const before = previewHex(operation.before);
      const after = previewHex(operation.after);
      const dataChange = byteRangeChanges[operation.index];
      return {
        index: operation.index,
        match_kind: operation.matchKind,
        file_offset: operation.fileOffset,
        bytes: operation.bytes,
        before_preview_hex: before.hex,
        after_preview_hex: after.hex,
        preview_truncated: before.truncated || after.truncated,
        container_entry: operation.containerEntry,
        note: operation.note,
        changes: (dataChange === undefined ? [] : [dataChange]).map(
          changeSummary,
        ),
      };
    }),
    changes: computed.value.changes.map(changeSummary),
    resulting: {
      sha256: computed.value.resultingSha256,
      bytes: computed.value.patchedBytes.length,
    },
    plan_digest: computed.value.planDigest,
    limitations: computed.value.limitations,
  });
  return ok(plan);
};

const verifyWrittenArtifact = async (
  path: string,
  plan: ArtifactPatchPlan,
  resources: ArtifactResourceScope,
  signal: AbortSignal | undefined,
  operation: ArtifactPatchOperation,
): Promise<
  Result<{ readonly sha256: string; readonly bytes: number }, AnalysisError>
> => {
  const written = await readArtifact(path, resources, signal, operation);
  if (!written.ok)
    return err(
      new ArtifactPatchError(
        operation,
        "verification_failed",
        path,
        "the artifact was written but could not be re-read for verification",
        { cause: written.error },
      ),
    );
  if (written.value.sha256 !== plan.resulting.sha256)
    return err(
      new ArtifactPatchError(
        operation,
        "verification_failed",
        path,
        `the written artifact digest is ${written.value.sha256}, not the planned ${plan.resulting.sha256}`,
        {
          diagnostics: {
            planned_sha256: plan.resulting.sha256,
            written_sha256: written.value.sha256,
          },
        },
      ),
    );
  const container = classifyArtifactContainer(written.value.bytes);
  const integrity = container.ok
    ? verifyContainerIntegrity(written.value.bytes, container.value)
    : undefined;
  if (integrity?.state === "mismatch")
    return err(
      new ArtifactPatchError(
        operation,
        "verification_failed",
        path,
        integrity.detail ?? "container framing did not verify after the write",
      ),
    );
  return ok({
    sha256: written.value.sha256,
    bytes: written.value.bytes.length,
  });
};

const planEvidence = (plan: ArtifactPatchPlan, path: string): Evidence =>
  createEvidence(
    { path, sha256: plan.target.sha256, format: "file" },
    PROVIDER,
    {
      predicateType: "rea.artifact-patch-plan",
      operation: PLAN_OPERATION,
      parameters: {
        target_path: path,
        target_sha256: plan.target.sha256,
        target_bytes: plan.target.bytes,
        container: plan.container.kind,
        operations: plan.operations.length,
        changes: plan.changes.length,
      },
      result: jsonValueSchema.parse(plan),
      rawResult: null,
      confidence: "derived",
      authority: "historical-reference",
      limitations: plan.limitations,
      locations: [{ kind: "artifact-path", path }],
    },
  );

const applyEvidence = (
  result: ArtifactPatchApplyResult,
  targetPath: string,
  written: {
    readonly previous?: {
      readonly sha256: string;
      readonly bytes: number;
    };
  },
): Evidence =>
  createEvidence(
    { path: targetPath, sha256: result.target.sha256, format: "file" },
    PROVIDER,
    {
      predicateType: "rea.artifact-patch-apply",
      operation: APPLY_OPERATION,
      parameters: {
        target_path: targetPath,
        artifact_path: result.artifact.path,
        artifact_sha256: result.artifact.sha256,
        mode: result.mode,
        plan_digest: result.plan_digest,
        operations: result.operations_applied,
        changes: result.changes_applied,
        ...(written.previous === undefined
          ? {}
          : { replaced_sha256: written.previous.sha256 }),
      },
      result: jsonValueSchema.parse(result),
      rawResult: null,
      confidence: "observed",
      authority: "historical-reference",
      limitations: result.limitations,
      locations: [
        { kind: "artifact-path", path: result.artifact.path },
        ...(result.artifact.path === targetPath
          ? []
          : [{ kind: "artifact-path" as const, path: targetPath }]),
      ],
    },
  );

const verifyEvidence = (
  result: ArtifactPatchVerifyResult,
  path: string,
): Evidence =>
  createEvidence(
    { path, sha256: result.target.sha256, format: "file" },
    PROVIDER,
    {
      predicateType: "rea.artifact-patch-verify",
      operation: VERIFY_OPERATION,
      parameters: {
        target_path: path,
        target_sha256: result.target.sha256,
        digest_state: result.digest.state,
        regions: result.regions.length,
        container: result.container.kind,
        container_integrity: result.container.integrity,
      },
      result: jsonValueSchema.parse(result),
      rawResult: null,
      confidence: "observed",
      authority: "historical-reference",
      limitations: result.limitations,
      locations: [{ kind: "artifact-path", path }],
    },
  );

const mapFailure = (
  cause: unknown,
  operation: ArtifactPatchOperation,
  path: string,
  signal: AbortSignal | undefined,
): AnalysisError => {
  if (cause instanceof ArtifactPatchError) return cause;
  if (signal?.aborted === true)
    return new AnalysisCancelledError(operation, { cause });
  if (cause instanceof ArtifactByteLimitError)
    return new AnalysisResourceConstraintError(
      operation,
      "memory",
      cause.message,
      {
        artifact_bytes: String(cause.bytes),
        limit: ARTIFACT_PATCH_LIMITS.artifactBytes,
      },
      {
        cause,
        remediationAction:
          "Select a smaller artifact; whole-file admission keeps every planned offset exact.",
      },
    );
  if (cause instanceof RegularFileWriteExistsError)
    return new AnalysisInputError(operation, { cause }, [
      {
        path: ["output_path"],
        reason: "invalid_value",
        message: `${cause.message}. Pass overwrite: true to replace it, or choose a new path.`,
      },
    ]);
  if (cause instanceof RegularFileWriteTargetError)
    return new AnalysisInputError(operation, { cause }, [
      {
        path: [
          cause.detail.includes("hard link") ? "target_path" : "output_path",
        ],
        reason: "invalid_value",
        message: cause.message,
      },
    ]);
  if (cause instanceof RegularFileReplacementChangedError)
    return new ArtifactPatchError(
      operation,
      "authority_required",
      path,
      cause.message,
      {
        cause,
      },
    );
  if (cause instanceof ArtifactReaderFailure && cause.cleanup !== undefined)
    return new ArtifactPatchError(operation, "io", path, cause.message, {
      cause,
      cleanup: cause.cleanup,
    });
  const code = errorCode(cause);
  if (code === "EACCES" || code === "EPERM")
    return new AnalysisAccessDeniedError(operation, path, code, { cause });
  if (
    cause instanceof NonRegularFileReadError ||
    cause instanceof RegularFileChangedError ||
    code === "ENOENT" ||
    code === "ENOTDIR" ||
    code === "EISDIR" ||
    code === "ELOOP"
  )
    return new AnalysisInputError(operation, { cause }, [
      {
        path: ["target_path"],
        reason: "invalid_value",
        message:
          cause instanceof NonRegularFileReadError ||
          cause instanceof RegularFileChangedError
            ? cause.message
            : `${path} could not be read as one regular artifact file (${code || "unknown"})`,
      },
    ]);
  if (cause instanceof z.ZodError)
    return new AnalysisOutputError(operation, cause.message, { cause });
  if (code !== "")
    return new ArtifactPatchError(operation, "io", path, errorMessage(cause), {
      cause,
    });
  return new ProviderAdapterError(PROVIDER.id, operation, {
    cause,
    diagnostics: {
      artifact_path: path,
      error_name: cause instanceof Error ? cause.name : "UnknownError",
      error_message: errorMessage(cause),
    },
  });
};
