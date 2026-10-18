import { createHash } from "node:crypto";
import { crc32 } from "node:zlib";

import canonicalize from "canonicalize";

import { ARTIFACT_PATCH_LIMITS } from "./artifactPatch.js";
import type { ArtifactPatchOperationInput } from "./artifactPatch.js";
import type { ArtifactContainer } from "./artifactPatchContainer.js";
import {
  classifyArtifactContainer,
  containerEntryForRange,
  containerFramingLimitations,
} from "./artifactPatchContainer.js";
import {
  refuseArtifactPatch,
  type ArtifactPatchRefusal,
} from "./artifactPatchRefusal.js";
import type { JsonValue } from "./jsonValue.js";
import { ok, type Result } from "./result.js";

/**
 * Pure equal-length byte mutation over an admitted artifact.
 *
 * The engine decides offsets and container framing from the artifact's own
 * bytes, refuses anything it cannot describe exactly, and returns the patched
 * bytes with the change manifest they were derived from. No filesystem,
 * process or network access happens here, so the same inputs always produce
 * the same plan digest and the same resulting bytes.
 */

/** Parse caller-validated even-length hex into exact bytes. */
export const parseHexBytes = (hex: string): Buffer => {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/u.test(hex))
    throw new TypeError("Hex bytes must be nonempty lowercase/uppercase pairs");
  return Buffer.from(hex, "hex");
};

const hex = (bytes: Buffer): string => bytes.toString("hex");

/** Bounded preview of one changed range, with truncation kept explicit. */
export const previewHex = (
  bytes: Buffer,
  limit = ARTIFACT_PATCH_LIMITS.previewBytes,
): { readonly hex: string; readonly truncated: boolean } =>
  bytes.length <= limit
    ? { hex: hex(bytes), truncated: false }
    : { hex: hex(bytes.subarray(0, limit)), truncated: true };

export interface PatchChange {
  readonly kind: "byte_range" | "zip_crc32";
  readonly containerEntry: string | null;
  readonly field: "data" | "local_header" | "central_directory";
  readonly offset: number;
  readonly before: Buffer;
  readonly after: Buffer;
}

export interface PlannedOperation {
  readonly index: number;
  readonly matchKind: "file_offset" | "unique_match" | "nth_match";
  readonly fileOffset: number;
  readonly bytes: number;
  readonly before: Buffer;
  readonly after: Buffer;
  readonly containerEntry: string | null;
  readonly note: string | null;
}

export interface ComputedArtifactPatchPlan {
  readonly container: ArtifactContainer;
  readonly operations: readonly PlannedOperation[];
  readonly changes: readonly PatchChange[];
  /** Bytes that would be written, with container framing already updated. */
  readonly patchedBytes: Buffer;
  readonly resultingSha256: string;
  readonly planDigest: string;
  readonly limitations: readonly string[];
}

export interface PlanArtifactPatchRequest {
  readonly targetSha256: string;
  readonly operations: readonly ArtifactPatchOperationInput[];
}

const MAX_PATTERN_OCCURRENCES_SEARCHED = 2;

const findOccurrences = (
  bytes: Buffer,
  pattern: Buffer,
  limit: number,
): readonly number[] => {
  const found: number[] = [];
  let from = 0;
  for (;;) {
    const at = bytes.indexOf(pattern, from);
    if (at === -1) return found;
    found.push(at);
    if (found.length >= limit) return found;
    from = at + 1;
  }
};

interface ResolvedSpan {
  readonly fileOffset: number;
  readonly before: Buffer;
  readonly after: Buffer;
  readonly matchKind: PlannedOperation["matchKind"];
  readonly containerEntry: string | null;
}

const resolveSpan = (
  bytes: Buffer,
  operation: ArtifactPatchOperationInput,
  container: ArtifactContainer,
): Result<ResolvedSpan, ArtifactPatchRefusal> => {
  const replacement = parseHexBytes(operation.replacement_hex);
  const located = (() => {
    if (operation.match.kind === "file_offset") {
      const expected = parseHexBytes(operation.match.expected_hex);
      if (expected.length !== replacement.length)
        return refuseArtifactPatch(
          "invalid_input",
          `file_offset selection expects ${expected.length} bytes but the replacement has ${replacement.length}`,
        );
      const offset = operation.match.offset;
      if (offset + expected.length > bytes.length)
        return refuseArtifactPatch(
          "expected_bytes_mismatch",
          `file_offset ${offset} with ${expected.length} bytes exceeds the artifact length ${bytes.length}`,
        );
      const actual = bytes.subarray(offset, offset + expected.length);
      if (!actual.equals(expected))
        return refuseArtifactPatch(
          "expected_bytes_mismatch",
          `bytes at file_offset ${offset} are ${hex(actual)} but ${hex(expected)} was expected`,
        );
      return ok({
        fileOffset: offset,
        before: expected,
        matchKind: "file_offset" as const,
      });
    }
    const pattern = parseHexBytes(operation.match.pattern_hex);
    if (pattern.length !== replacement.length)
      return refuseArtifactPatch(
        "invalid_input",
        `pattern selection covers ${pattern.length} bytes but the replacement has ${replacement.length}`,
      );
    const unique = operation.match.kind === "unique_match";
    const requestedOccurrence =
      operation.match.kind === "nth_match" ? operation.match.occurrence : 1;
    const found = findOccurrences(
      bytes,
      pattern,
      unique ? MAX_PATTERN_OCCURRENCES_SEARCHED : requestedOccurrence,
    );
    if (unique && found.length !== 1)
      return refuseArtifactPatch(
        "match_unresolved",
        found.length === 0
          ? "pattern does not occur in the artifact"
          : `pattern occurs more than once (at least ${found.length}); use nth_match with an occurrence or file_offset`,
      );
    if (!unique && found.length < requestedOccurrence)
      return refuseArtifactPatch(
        "match_unresolved",
        `pattern occurs ${found.length} time(s), fewer than the requested occurrence ${requestedOccurrence}`,
      );
    const fileOffset = unique ? found[0] : found[found.length - 1];
    if (fileOffset === undefined)
      return refuseArtifactPatch(
        "match_unresolved",
        "pattern selection resolved no range",
      );
    return ok({
      fileOffset,
      before: pattern,
      matchKind: unique ? ("unique_match" as const) : ("nth_match" as const),
    });
  })();
  if (!located.ok) return located;
  const entry = containerEntryForRange(
    container,
    located.value.fileOffset,
    replacement.length,
  );
  return entry.ok
    ? ok({ ...located.value, after: replacement, containerEntry: entry.value })
    : entry;
};

const uint32Le = (value: number): Buffer => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value, 0);
  return bytes;
};

const limitationsFor = (container: ArtifactContainer): readonly string[] => [
  "Only equal-length replacement is supported. Insertions, deletions, repacking and execution of the artifact are out of scope.",
  "A written artifact is verified byte-for-byte against this plan; this workflow never runs, installs or loads it.",
  ...containerFramingLimitations(container),
];

/** Resolve, validate and compute one patch plan without touching the disk. */
export const planArtifactPatch = (
  bytes: Buffer,
  request: PlanArtifactPatchRequest,
): Result<ComputedArtifactPatchPlan, ArtifactPatchRefusal> => {
  const container = classifyArtifactContainer(bytes);
  if (!container.ok) return container;
  const resolved: ResolvedSpan[] = [];
  for (const [index, operation] of request.operations.entries()) {
    const span = resolveSpan(bytes, operation, container.value);
    if (!span.ok)
      return refuseArtifactPatch(
        span.error.reason,
        `operation ${index}: ${span.error.detail}`,
      );
    resolved.push(span.value);
  }
  const ordered = [...resolved.entries()].sort(
    (left, right) => left[1].fileOffset - right[1].fileOffset,
  );
  for (let index = 1; index < ordered.length; index += 1) {
    const previous = ordered[index - 1];
    const current = ordered[index];
    if (previous === undefined || current === undefined) continue;
    if (
      current[1].fileOffset <
      previous[1].fileOffset + previous[1].before.length
    )
      return refuseArtifactPatch(
        "overlap",
        `operations ${previous[0]} and ${current[0]} replace overlapping ranges at ${previous[1].fileOffset} and ${current[1].fileOffset}`,
      );
  }
  const patched = Buffer.from(bytes);
  for (const span of resolved) span.after.copy(patched, span.fileOffset);
  const changes: PatchChange[] = resolved.map((span) => ({
    kind: "byte_range",
    containerEntry: span.containerEntry,
    field: "data",
    offset: span.fileOffset,
    before: span.before,
    after: span.after,
  }));
  if (container.value.kind === "zip") {
    const touched = new Set(
      resolved
        .map(({ containerEntry }) => containerEntry)
        .filter((entry): entry is string => entry !== null),
    );
    for (const member of container.value.members) {
      if (!touched.has(member.path)) continue;
      const data = patched.subarray(
        member.dataOffset,
        member.dataOffset + member.compressedBytes,
      );
      const updated = crc32(data);
      const localBefore = bytes.subarray(
        member.localHeaderOffset + 14,
        member.localHeaderOffset + 18,
      );
      const centralBefore = bytes.subarray(
        member.centralDirectoryOffset + 16,
        member.centralDirectoryOffset + 20,
      );
      const after = uint32Le(updated);
      after.copy(patched, member.localHeaderOffset + 14);
      after.copy(patched, member.centralDirectoryOffset + 16);
      changes.push(
        {
          kind: "zip_crc32",
          containerEntry: member.path,
          field: "local_header",
          offset: member.localHeaderOffset + 14,
          before: Buffer.from(localBefore),
          after: Buffer.from(after),
        },
        {
          kind: "zip_crc32",
          containerEntry: member.path,
          field: "central_directory",
          offset: member.centralDirectoryOffset + 16,
          before: Buffer.from(centralBefore),
          after: Buffer.from(uint32Le(updated)),
        },
      );
    }
  }
  const resultingSha256 = createHash("sha256").update(patched).digest("hex");
  const operations: PlannedOperation[] = resolved.map((span, index) => ({
    index,
    matchKind: span.matchKind,
    fileOffset: span.fileOffset,
    bytes: span.after.length,
    before: span.before,
    after: span.after,
    containerEntry: span.containerEntry,
    note: request.operations[index]?.note ?? null,
  }));
  const digestInput: JsonValue = {
    target_sha256: request.targetSha256,
    container: container.value.kind,
    resulting_sha256: resultingSha256,
    operations: operations.map((operation) => ({
      index: operation.index,
      match_kind: operation.matchKind,
      file_offset: operation.fileOffset,
      bytes: operation.bytes,
      before_sha256: createHash("sha256")
        .update(operation.before)
        .digest("hex"),
      after_sha256: createHash("sha256").update(operation.after).digest("hex"),
      container_entry: operation.containerEntry,
    })),
    changes: changes.map((change) => ({
      kind: change.kind,
      container_entry: change.containerEntry,
      field: change.field,
      offset: change.offset,
      before_hex: hex(change.before),
      after_hex: hex(change.after),
    })),
  };
  const encoded = canonicalize(digestInput);
  if (encoded === undefined)
    throw new TypeError("Artifact patch plan is not canonical JSON");
  return ok({
    container: container.value,
    operations,
    changes,
    patchedBytes: patched,
    resultingSha256,
    planDigest: createHash("sha256").update(encoded).digest("hex"),
    limitations: limitationsFor(container.value),
  });
};

export interface VerifiedRegion {
  readonly fileOffset: number;
  readonly expected: Buffer;
  readonly actual: Buffer;
}

/** Compare expected bytes against the artifact without writing anything. */
export const verifyArtifactPatchRegions = (
  bytes: Buffer,
  regions: readonly {
    readonly fileOffset: number;
    readonly expected: Buffer;
  }[],
): readonly VerifiedRegion[] =>
  regions.map(({ fileOffset, expected }) => ({
    fileOffset,
    expected,
    actual: Buffer.from(
      bytes.subarray(
        fileOffset,
        Math.min(fileOffset + expected.length, bytes.length),
      ),
    ),
  }));
