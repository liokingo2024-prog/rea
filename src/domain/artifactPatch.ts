import { z } from "zod";

import { digestSchema } from "./digests.js";
import { localPathStringSchema } from "./localPath.js";

/**
 * Hard bounds for caller-directed artifact mutation. Every bound is a real
 * resource constraint of this workflow: the artifact is admitted whole, the
 * plan and its change manifest are returned inline to an agent, and each
 * replacement has to remain verifiable from the returned evidence.
 */
export const ARTIFACT_PATCH_LIMITS = Object.freeze({
  /** Largest admitted artifact; whole-file admission keeps offsets exact. */
  artifactBytes: 512 * 1024 * 1024,
  operations: 256,
  replacementBytes: 1024 * 1024,
  totalReplacementBytes: 4 * 1024 * 1024,
  /** Pattern length bound for match-based selections. */
  patternBytes: 4096,
  /** Bounded ASAR header admission. */
  asarHeaderBytes: 8 * 1024 * 1024,
  /** Verification regions returned inline. */
  regions: 1024,
  /** Hex preview per changed range; the exact length is always reported. */
  previewBytes: 64,
});

const nonNegativeOffset = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER)
  .describe("Zero-based byte offset from the start of the artifact");

/** Even-length lowercase/uppercase hex byte pairs without separators. */
const hexBytes = (maximumBytes: number) =>
  z
    .string()
    .regex(/^(?:[0-9a-fA-F]{2})+$/u)
    .max(maximumBytes * 2);

const replacementHex = hexBytes(
  ARTIFACT_PATCH_LIMITS.replacementBytes,
).describe(
  "Replacement bytes as hex pairs; must be exactly as long as the selected range",
);

const patternHex = hexBytes(ARTIFACT_PATCH_LIMITS.patternBytes).describe(
  "Literal bytes to locate as hex pairs; wildcards are not accepted because every selected byte must be verified",
);

/** How one replacement range is selected inside the artifact. */
export const artifactPatchMatchSchema = z
  .discriminatedUnion("kind", [
    z.strictObject({
      kind: z.literal("file_offset"),
      offset: nonNegativeOffset,
      expected_hex: hexBytes(ARTIFACT_PATCH_LIMITS.replacementBytes).describe(
        "Bytes that must already exist at offset; their length is the replaced range",
      ),
    }),
    z.strictObject({
      kind: z.literal("unique_match"),
      pattern_hex: patternHex,
    }),
    z.strictObject({
      kind: z.literal("nth_match"),
      pattern_hex: patternHex,
      occurrence: z
        .number()
        .int()
        .min(1)
        .max(1_000_000)
        .describe(
          "One-based occurrence index when the pattern appears more than once",
        ),
    }),
  ])
  .describe("Selection of the exact byte range this operation replaces");

/** One equal-length replacement of already verified artifact bytes. */
export const artifactPatchOperationSchema = z.strictObject({
  match: artifactPatchMatchSchema,
  replacement_hex: replacementHex,
  note: z
    .string()
    .min(1)
    .max(200)
    .optional()
    .describe("Caller note retained in the plan and change manifest"),
});
export type ArtifactPatchOperationInput = z.output<
  typeof artifactPatchOperationSchema
>;

const operations = z
  .array(artifactPatchOperationSchema)
  .min(1)
  .max(ARTIFACT_PATCH_LIMITS.operations)
  .describe("Equal-length replacements applied together in one plan");

/** Plan a mutation without writing anything. */
export const planArtifactPatchInputSchema = z.strictObject({
  target_path: localPathStringSchema.describe(
    "Absolute path to the artifact to plan against; the file is read and never written",
  ),
  operations,
});
export type PlanArtifactPatchInput = z.output<
  typeof planArtifactPatchInputSchema
>;

/** Apply a plan to a copy, or in place under explicit authority. */
export const applyArtifactPatchInputSchema = z.strictObject({
  target_path: localPathStringSchema.describe(
    "Absolute path to the artifact whose bytes are mutated; must still match the planned artifact",
  ),
  operations,
  plan_digest: digestSchema
    .optional()
    .describe(
      "plan_digest returned by plan_artifact_patch; when supplied, the artifact and operations must still produce exactly that plan",
    ),
  output_path: localPathStringSchema
    .optional()
    .describe(
      "Absolute path for the patched copy; required unless in_place is true. The target is left untouched",
    ),
  overwrite: z
    .boolean()
    .default(false)
    .describe(
      "Replace an existing output_path; the target itself is never overwritten by a copy",
    ),
  in_place: z
    .boolean()
    .default(false)
    .describe(
      "Mutate target_path itself instead of writing a copy; requires explicit acknowledgements",
    ),
  acknowledge_in_place: z
    .boolean()
    .default(false)
    .describe(
      "Confirm that the target artifact may be irreversibly modified on disk",
    ),
  expected_target_sha256: digestSchema
    .optional()
    .describe(
      "Required for in_place: the sha256 the target must still have immediately before the replacement",
    ),
});
export type ApplyArtifactPatchInput = z.output<
  typeof applyArtifactPatchInputSchema
>;

/** Re-check a written artifact against an expected digest and byte regions. */
export const verifyArtifactPatchInputSchema = z.strictObject({
  target_path: localPathStringSchema.describe(
    "Absolute path to the artifact to verify; the file is read and never written",
  ),
  expected_sha256: digestSchema
    .optional()
    .describe(
      "Digest the artifact must have; omit for region-only verification",
    ),
  regions: z
    .array(
      z.strictObject({
        file_offset: nonNegativeOffset,
        expected_hex: hexBytes(ARTIFACT_PATCH_LIMITS.replacementBytes).describe(
          "Bytes that must exist at file_offset",
        ),
      }),
    )
    .max(ARTIFACT_PATCH_LIMITS.regions)
    .default([])
    .describe("Byte regions that must already equal the expected bytes"),
});
export type VerifyArtifactPatchInput = z.output<
  typeof verifyArtifactPatchInputSchema
>;

/** Identity of one artifact as read, without its bytes. */
export const artifactIdentitySchema = z.strictObject({
  path: z.string().min(1),
  sha256: digestSchema,
  bytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
});

/** How the admitted bytes frame their payload. */
export const artifactContainerSchema = z.strictObject({
  kind: z.enum(["flat", "zip", "asar"]),
  entries: z.number().int().nonnegative().nullable(),
  limitations: z.array(z.string().min(1)),
});

export const artifactPatchChangeSchema = z.strictObject({
  kind: z.enum(["byte_range", "zip_crc32"]),
  container_entry: z.string().nullable(),
  field: z.enum(["data", "local_header", "central_directory"]),
  offset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  bytes: z.number().int().min(1),
  before_hex: z.string().min(1),
  after_hex: z.string().min(1),
});

export const plannedArtifactPatchOperationSchema = z.strictObject({
  index: z.number().int().nonnegative(),
  match_kind: z.enum(["file_offset", "unique_match", "nth_match"]),
  file_offset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  bytes: z.number().int().min(1),
  before_preview_hex: z.string().min(1),
  after_preview_hex: z.string().min(1),
  preview_truncated: z.boolean(),
  container_entry: z.string().nullable(),
  note: z.string().nullable(),
  changes: z.array(artifactPatchChangeSchema),
});

/** Verified plan over exact bytes; plan_digest binds a later apply. */
export const artifactPatchPlanSchema = z.strictObject({
  target: artifactIdentitySchema,
  container: artifactContainerSchema,
  operations: z.array(plannedArtifactPatchOperationSchema),
  changes: z.array(artifactPatchChangeSchema),
  resulting: z.strictObject({
    sha256: digestSchema,
    bytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  }),
  plan_digest: digestSchema,
  limitations: z.array(z.string().min(1)),
});
export type ArtifactPatchPlan = z.output<typeof artifactPatchPlanSchema>;

export const artifactPatchApplyResultSchema = z.strictObject({
  plan_digest: digestSchema,
  mode: z.enum(["copy", "in_place"]),
  target: artifactIdentitySchema,
  artifact: artifactIdentitySchema,
  operations_applied: z.number().int().min(1),
  changes_applied: z.number().int().nonnegative(),
  container: artifactContainerSchema,
  verification: z.strictObject({
    state: z.literal("verified"),
    regions_verified: z.number().int().min(1),
    expected_sha256: digestSchema,
  }),
  limitations: z.array(z.string().min(1)),
});
export type ArtifactPatchApplyResult = z.output<
  typeof artifactPatchApplyResultSchema
>;

export const artifactPatchVerifyResultSchema = z.strictObject({
  target: artifactIdentitySchema,
  digest: z.strictObject({
    state: z.enum(["matches", "mismatch", "not_requested"]),
    expected_sha256: digestSchema.nullable(),
    actual_sha256: digestSchema,
  }),
  regions: z.array(
    z.strictObject({
      file_offset: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
      expected_hex: z.string().min(1),
      actual_hex: z.string().min(1),
      state: z.enum(["matches", "mismatch"]),
    }),
  ),
  container: z.strictObject({
    kind: z.enum(["flat", "zip", "asar"]),
    integrity: z.enum(["verified", "mismatch", "not_applicable", "unknown"]),
    entries_checked: z.number().int().nonnegative(),
    limitations: z.array(z.string().min(1)),
  }),
  limitations: z.array(z.string().min(1)),
});
export type ArtifactPatchVerifyResult = z.output<
  typeof artifactPatchVerifyResultSchema
>;
