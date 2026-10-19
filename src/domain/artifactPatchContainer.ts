import { crc32, inflateRawSync } from "node:zlib";

import { ARTIFACT_PATCH_LIMITS } from "./artifactPatch.js";
import {
  refuseArtifactPatch,
  type ArtifactPatchRefusal,
} from "./artifactPatchRefusal.js";
import { ok, type Result } from "./result.js";

/**
 * Container framing for equal-length artifact mutation.
 *
 * ZIP and ASAR payloads are parsed from the artifact's own bytes so a
 * planned span can name the entry it changes, so framing updates are derived
 * instead of guessed, and so anything this workflow cannot describe exactly is
 * refused before any byte is written.
 */

/** How the admitted bytes frame their payload. */
export interface FlatContainer {
  readonly kind: "flat";
}

export interface ZipMember {
  readonly path: string;
  readonly flags: number;
  readonly method: number;
  readonly crc32: number;
  readonly compressedBytes: number;
  readonly uncompressedBytes: number;
  readonly localHeaderOffset: number;
  readonly centralDirectoryOffset: number;
  readonly dataOffset: number;
}

export interface ZipContainer {
  readonly kind: "zip";
  readonly members: readonly ZipMember[];
  readonly centralDirectoryOffset: number;
  readonly centralDirectoryBytes: number;
}

export interface AsarFile {
  readonly path: string;
  readonly offset: number;
  readonly size: number;
  readonly declaresIntegrity: boolean;
}

export interface AsarContainer {
  readonly kind: "asar";
  readonly headerEnd: number;
  readonly files: readonly AsarFile[];
  readonly unmodeledEntries: readonly string[];
}

export type ArtifactContainer = FlatContainer | ZipContainer | AsarContainer;

const ZIP_LOCAL_FILE_HEADER = 0x04034b50;
const ZIP_CENTRAL_DIRECTORY_HEADER = 0x02014b50;
const ZIP_END_OF_CENTRAL_DIRECTORY = 0x06054b50;
const ZIP_FLAG_ENCRYPTED = 0x0001;
const ZIP_FLAG_DATA_DESCRIPTOR = 0x0008;
const ZIP_METHOD_STORED = 0;
const ZIP_METHOD_DEFLATED = 8;

const findEndOfCentralDirectory = (bytes: Buffer): number | undefined => {
  const earliest = Math.max(0, bytes.length - 22 - 0xffff);
  for (let offset = bytes.length - 22; offset >= earliest; offset -= 1) {
    if (
      bytes.readUInt32LE(offset) === ZIP_END_OF_CENTRAL_DIRECTORY &&
      bytes.length - (offset + 22) === bytes.readUInt16LE(offset + 20)
    )
      return offset;
  }
  return undefined;
};

const isJsonObject = (
  value: unknown,
): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const readZipContainer = (
  bytes: Buffer,
): Result<ZipContainer, ArtifactPatchRefusal> => {
  const end = findEndOfCentralDirectory(bytes);
  if (end === undefined)
    return refuseArtifactPatch(
      "container_unsupported",
      "No ZIP end-of-central-directory record was found",
    );
  const entries = bytes.readUInt16LE(end + 10);
  const centralDirectoryBytes = bytes.readUInt32LE(end + 12);
  const centralDirectoryOffset = bytes.readUInt32LE(end + 16);
  if (
    entries === 0xffff ||
    centralDirectoryBytes === 0xffffffff ||
    centralDirectoryOffset === 0xffffffff
  )
    return refuseArtifactPatch(
      "container_unsupported",
      "ZIP64 containers are not supported; rebuild the archive without ZIP64 extensions",
    );
  if (
    entries === 0 ||
    centralDirectoryOffset + centralDirectoryBytes > end ||
    centralDirectoryOffset > bytes.length
  )
    return refuseArtifactPatch(
      "container_unsupported",
      "ZIP central directory lies outside the admitted bytes",
    );
  const members: ZipMember[] = [];
  let offset = centralDirectoryOffset;
  for (let index = 0; index < entries; index += 1) {
    if (
      offset + 46 > bytes.length ||
      bytes.readUInt32LE(offset) !== ZIP_CENTRAL_DIRECTORY_HEADER
    )
      return refuseArtifactPatch(
        "container_unsupported",
        `ZIP central directory entry ${index} is malformed`,
      );
    const flags = bytes.readUInt16LE(offset + 8);
    const method = bytes.readUInt16LE(offset + 10);
    const memberCrc = bytes.readUInt32LE(offset + 16);
    const compressedBytes = bytes.readUInt32LE(offset + 20);
    const uncompressedBytes = bytes.readUInt32LE(offset + 24);
    const nameBytes = bytes.readUInt16LE(offset + 28);
    const extraBytes = bytes.readUInt16LE(offset + 30);
    const commentBytes = bytes.readUInt16LE(offset + 32);
    const localHeaderOffset = bytes.readUInt32LE(offset + 42);
    if (offset + 46 + nameBytes > bytes.length)
      return refuseArtifactPatch(
        "container_unsupported",
        `ZIP central directory entry ${index} name overruns the admitted bytes`,
      );
    const path = bytes.toString("utf8", offset + 46, offset + 46 + nameBytes);
    if (
      localHeaderOffset + 30 > bytes.length ||
      bytes.readUInt32LE(localHeaderOffset) !== ZIP_LOCAL_FILE_HEADER
    )
      return refuseArtifactPatch(
        "container_unsupported",
        `ZIP local header for entry ${path} is missing or malformed`,
      );
    const localNameBytes = bytes.readUInt16LE(localHeaderOffset + 26);
    const localExtraBytes = bytes.readUInt16LE(localHeaderOffset + 28);
    const dataOffset =
      localHeaderOffset + 30 + localNameBytes + localExtraBytes;
    if (dataOffset + compressedBytes > centralDirectoryOffset)
      return refuseArtifactPatch(
        "container_unsupported",
        `ZIP entry ${path} data overruns the central directory`,
      );
    if (bytes.readUInt16LE(localHeaderOffset + 8) !== method)
      return refuseArtifactPatch(
        "container_unsupported",
        `ZIP entry ${path} declares method ${method} in the central directory but ${bytes.readUInt16LE(localHeaderOffset + 8)} in its local header`,
      );
    members.push({
      path,
      flags,
      method,
      crc32: memberCrc,
      compressedBytes,
      uncompressedBytes,
      localHeaderOffset,
      centralDirectoryOffset: offset,
      dataOffset,
    });
    offset += 46 + nameBytes + extraBytes + commentBytes;
  }
  return ok({
    kind: "zip",
    members,
    centralDirectoryOffset,
    centralDirectoryBytes,
  });
};

/**
 * Detect an ASAR payload. Detection requires the 4-byte header size, a valid
 * UTF-8 JSON object whose only top-level key is `files`, and bounded offsets,
 * so unrelated flat files are not mistaken for archives.
 */
const readAsarContainer = (
  bytes: Buffer,
): Result<AsarContainer | undefined, ArtifactPatchRefusal> => {
  if (bytes.length < 16) return ok(undefined);
  // ASAR framing: [outer pickle payload size = 4][header pickle length]
  // [header payload size][JSON length][JSON][padding][file data…].
  if (bytes.readUInt32LE(0) !== 4) return ok(undefined);
  const archiveHeaderBytes = bytes.readUInt32LE(4);
  if (
    archiveHeaderBytes < 12 ||
    archiveHeaderBytes >
      Math.min(bytes.length - 8, ARTIFACT_PATCH_LIMITS.asarHeaderBytes)
  )
    return ok(undefined);
  if (bytes.readUInt32LE(8) !== archiveHeaderBytes - 4) return ok(undefined);
  const jsonBytes = bytes.readUInt32LE(12);
  if (jsonBytes < 2 || jsonBytes > archiveHeaderBytes - 8) return ok(undefined);
  const jsonStart = 16;
  let parsed: unknown;
  try {
    parsed = JSON.parse(
      bytes.toString("utf8", jsonStart, jsonStart + jsonBytes),
    );
  } catch {
    return ok(undefined);
  }
  if (!isJsonObject(parsed)) return ok(undefined);
  const keys = Object.keys(parsed);
  if (keys.length !== 1 || keys[0] !== "files") return ok(undefined);
  if (!isJsonObject(parsed["files"])) return ok(undefined);
  const headerEnd = 8 + archiveHeaderBytes;
  const dataBytes = bytes.length - headerEnd;
  const files: AsarFile[] = [];
  const unmodeledEntries: string[] = [];
  const pending: { path: string; node: Readonly<Record<string, unknown>> }[] = [
    { path: "", node: parsed["files"] },
  ];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) break;
    for (const [name, child] of Object.entries(current.node)) {
      const path = current.path === "" ? name : `${current.path}/${name}`;
      if (!isJsonObject(child)) {
        unmodeledEntries.push(path);
        continue;
      }
      if (isJsonObject(child["files"])) {
        pending.push({ path, node: child["files"] });
        continue;
      }
      if (child["unpacked"] === true || typeof child["link"] === "string") {
        unmodeledEntries.push(path);
        continue;
      }
      if (
        typeof child["offset"] === "string" &&
        typeof child["size"] === "number"
      ) {
        const offset = Number(child["offset"]);
        const size = child["size"];
        if (
          !Number.isSafeInteger(offset) ||
          offset < 0 ||
          !Number.isSafeInteger(size) ||
          size < 0 ||
          offset + size > dataBytes
        )
          return refuseArtifactPatch(
            "container_unsupported",
            `ASAR entry ${path} declares an out-of-bounds offset or size`,
          );
        files.push({
          path,
          offset,
          size,
          declaresIntegrity: isJsonObject(child["integrity"]),
        });
        continue;
      }
      unmodeledEntries.push(path);
    }
  }
  return ok({ kind: "asar", headerEnd, files, unmodeledEntries });
};

/** Classify the admitted bytes, refusing only what cannot be described. */
export const classifyArtifactContainer = (
  bytes: Buffer,
): Result<ArtifactContainer, ArtifactPatchRefusal> => {
  if (
    bytes.length >= 22 &&
    (bytes.readUInt32LE(0) === ZIP_LOCAL_FILE_HEADER ||
      bytes.readUInt32LE(0) === ZIP_END_OF_CENTRAL_DIRECTORY)
  )
    return readZipContainer(bytes);
  const asar = readAsarContainer(bytes);
  if (!asar.ok) return asar;
  return ok(asar.value ?? { kind: "flat" });
};

/**
 * Map one planned range to the container entry that owns it, or refuse.
 *
 * A plan can only name a ZIP member or ASAR file when the range is entirely
 * inside modeled, patchable data; framing bytes and entries whose framing this
 * workflow cannot update are refused here rather than discovered at write time.
 */
export const containerEntryForRange = (
  container: ArtifactContainer,
  offset: number,
  length: number,
): Result<string | null, ArtifactPatchRefusal> => {
  if (container.kind === "flat") return ok(null);
  if (container.kind === "asar") {
    const file = container.files.find(
      (candidate) =>
        offset >= container.headerEnd + candidate.offset &&
        offset + length <=
          container.headerEnd + candidate.offset + candidate.size,
    );
    if (file === undefined)
      return refuseArtifactPatch(
        "container_unsupported",
        "The selected range lies in ASAR header bytes, padding or an unmodeled entry; only modeled file data is patchable",
      );
    if (file.declaresIntegrity)
      return refuseArtifactPatch(
        "container_unsupported",
        `ASAR entry ${file.path} declares integrity metadata; replacing its bytes would contradict that hash`,
      );
    return ok(file.path);
  }
  const member = container.members.find(
    (candidate) =>
      offset >= candidate.dataOffset &&
      offset + length <= candidate.dataOffset + candidate.compressedBytes,
  );
  if (member === undefined)
    return refuseArtifactPatch(
      "container_unsupported",
      "The selected range lies in ZIP framing, a member that is not compared byte-exact, or outside member data",
    );
  if ((member.flags & ZIP_FLAG_ENCRYPTED) !== 0)
    return refuseArtifactPatch(
      "container_unsupported",
      `ZIP entry ${member.path} is encrypted`,
    );
  if ((member.flags & ZIP_FLAG_DATA_DESCRIPTOR) !== 0)
    return refuseArtifactPatch(
      "container_unsupported",
      `ZIP entry ${member.path} stores its sizes in a data descriptor`,
    );
  if (member.method !== ZIP_METHOD_STORED)
    return refuseArtifactPatch(
      "container_unsupported",
      `ZIP entry ${member.path} uses compression method ${member.method}; only stored entries are patchable without repacking`,
    );
  return ok(member.path);
};

/**
 * What this workflow does and does not keep true for one container framing.
 * Stated once here so plans, applied results and verification report the same
 * limitations instead of restating them per adapter.
 */
export const containerFramingLimitations = (
  container: ArtifactContainer,
): readonly string[] => {
  if (container.kind === "zip")
    return [
      "Zip member data is replaced with the stored CRC-32 of every changed stored entry updated in its local header and central directory record.",
      "Archive-level signatures and digest manifests are not updated; a patched APK, JAR or IPA is unsigned until it is re-signed.",
      "Only stored (uncompressed) entries are patchable; compressed, encrypted and data-descriptor entries are refused.",
      `Container integrity is re-derived from the artifact's own bytes: each member's CRC-32 is recomputed over its stored bytes or its inflated deflate stream, within a ${ARTIFACT_PATCH_LIMITS.verificationInflatedBytes} byte inflation budget; members that are encrypted, use another compression method or exceed that budget leave the container unknown instead of verified.`,
    ];
  if (container.kind === "asar")
    return [
      "ASAR offsets stay valid because replacements preserve length; entries declaring integrity metadata, unpacked entries and links are refused or excluded.",
      "Electron ASAR integrity fuses and companion files outside the archive are not verified by this workflow.",
    ];
  return [
    "The artifact is treated as flat bytes: format-level checksums, signatures or embedded integrity records inside the replaced bytes are not updated by this workflow.",
  ];
};

export interface ContainerIntegrity {
  readonly state: "verified" | "mismatch" | "not_applicable" | "unknown";
  readonly entriesChecked: number;
  readonly detail: string | null;
}

/**
 * Read one member's framing claims straight from the bytes under verification.
 *
 * The container only supplies entry topology (name, offsets). Every recorded
 * CRC-32, size, method and flag is re-read from the artifact being checked, so
 * a container parsed from earlier bytes cannot lend a stale claim to the
 * verdict.
 */
interface ZipMemberClaims {
  readonly flags: number;
  readonly method: number;
  readonly crc32: number;
  readonly compressedBytes: number;
  readonly uncompressedBytes: number;
  readonly localFlags: number;
  readonly localMethod: number;
  readonly localCrc32: number;
  readonly localCompressedBytes: number;
  readonly localUncompressedBytes: number;
}

const readZipMemberClaims = (
  bytes: Buffer,
  member: ZipMember,
): ZipMemberClaims => ({
  flags: bytes.readUInt16LE(member.centralDirectoryOffset + 8),
  method: bytes.readUInt16LE(member.centralDirectoryOffset + 10),
  crc32: bytes.readUInt32LE(member.centralDirectoryOffset + 16),
  compressedBytes: bytes.readUInt32LE(member.centralDirectoryOffset + 20),
  uncompressedBytes: bytes.readUInt32LE(member.centralDirectoryOffset + 24),
  localFlags: bytes.readUInt16LE(member.localHeaderOffset + 6),
  localMethod: bytes.readUInt16LE(member.localHeaderOffset + 8),
  localCrc32: bytes.readUInt32LE(member.localHeaderOffset + 14),
  localCompressedBytes: bytes.readUInt32LE(member.localHeaderOffset + 18),
  localUncompressedBytes: bytes.readUInt32LE(member.localHeaderOffset + 22),
});

const zipMemberDisagreement = (
  member: ZipMember,
  claims: ZipMemberClaims,
): string | null => {
  if (claims.localMethod !== claims.method)
    return `ZIP entry ${member.path} declares compression method ${claims.method} in the central directory but ${claims.localMethod} in its local header`;
  // A member with a data descriptor records placeholder CRC-32 and sizes in its
  // local header, so those fields carry no claim to compare.
  if ((claims.localFlags & ZIP_FLAG_DATA_DESCRIPTOR) !== 0) return null;
  if (
    claims.localCrc32 === claims.crc32 &&
    claims.localCompressedBytes === claims.compressedBytes &&
    claims.localUncompressedBytes === claims.uncompressedBytes
  )
    return null;
  return `ZIP entry ${member.path} local header records CRC-32 0x${claims.localCrc32.toString(16)} and ${claims.localCompressedBytes}/${claims.localUncompressedBytes} bytes but its central directory record holds 0x${claims.crc32.toString(16)} and ${claims.compressedBytes}/${claims.uncompressedBytes} bytes`;
};

const zipMemberMismatch = (
  detail: string,
  entriesChecked: number,
): ContainerIntegrity => ({
  state: "mismatch",
  entriesChecked,
  detail,
});

/**
 * Re-derive container framing integrity from the artifact's own bytes.
 *
 * Every member is CRC-verified from its own bytes: stored members directly,
 * deflate members by inflating them within a bounded budget. Members that
 * cannot be checked this way (encrypted, another compression method, or beyond
 * the inflation budget) leave the container `unknown` rather than verified, so
 * a caller never reads a stronger claim than the bytes support.
 */
export const verifyContainerIntegrity = (
  bytes: Buffer,
  container: ArtifactContainer,
): ContainerIntegrity => {
  if (container.kind === "flat")
    return { state: "not_applicable", entriesChecked: 0, detail: null };
  if (container.kind === "asar") {
    const reparsed = readAsarContainer(bytes);
    return reparsed.ok && reparsed.value !== undefined
      ? {
          state: "verified",
          entriesChecked: reparsed.value.files.length,
          detail: null,
        }
      : {
          state: "unknown",
          entriesChecked: 0,
          detail: "ASAR header could not be re-derived from the written bytes",
        };
  }
  let checked = 0;
  let inflatedBytes = 0;
  const unchecked: string[] = [];
  for (const member of container.members) {
    const claims = readZipMemberClaims(bytes, member);
    const disagreement = zipMemberDisagreement(member, claims);
    if (disagreement !== null) return zipMemberMismatch(disagreement, checked);
    const dataEnd = member.dataOffset + claims.compressedBytes;
    if (dataEnd > member.centralDirectoryOffset)
      return zipMemberMismatch(
        `ZIP entry ${member.path} records ${claims.compressedBytes} compressed bytes from offset ${member.dataOffset}, into or past the central directory at ${member.centralDirectoryOffset}`,
        checked,
      );
    if ((claims.flags & ZIP_FLAG_ENCRYPTED) !== 0) {
      unchecked.push(`${member.path} is encrypted`);
      continue;
    }
    const data = bytes.subarray(member.dataOffset, dataEnd);
    if (claims.method === ZIP_METHOD_STORED) {
      const computed = crc32(data);
      if (computed !== claims.crc32)
        return zipMemberMismatch(
          `ZIP entry ${member.path} CRC-32 is 0x${computed.toString(16)} over its ${claims.compressedBytes} stored bytes but 0x${claims.crc32.toString(16)} is recorded`,
          checked + 1,
        );
      checked += 1;
      continue;
    }
    if (claims.method !== ZIP_METHOD_DEFLATED) {
      unchecked.push(`${member.path} uses compression method ${claims.method}`);
      continue;
    }
    if (
      claims.uncompressedBytes >
      ARTIFACT_PATCH_LIMITS.verificationInflatedBytes - inflatedBytes
    ) {
      unchecked.push(
        `${member.path} declares ${claims.uncompressedBytes} inflated bytes beyond the ${ARTIFACT_PATCH_LIMITS.verificationInflatedBytes} byte verification budget`,
      );
      continue;
    }
    let inflated: Buffer;
    try {
      inflated = inflateRawSync(data, {
        maxOutputLength: Math.max(claims.uncompressedBytes, 1),
      });
    } catch {
      return zipMemberMismatch(
        `ZIP entry ${member.path} is not a readable deflate stream of its declared ${claims.uncompressedBytes} bytes`,
        checked + 1,
      );
    }
    inflatedBytes += inflated.length;
    if (inflated.length !== claims.uncompressedBytes)
      return zipMemberMismatch(
        `ZIP entry ${member.path} inflates to ${inflated.length} bytes but records ${claims.uncompressedBytes}`,
        checked + 1,
      );
    const computed = crc32(inflated);
    if (computed !== claims.crc32)
      return zipMemberMismatch(
        `ZIP entry ${member.path} CRC-32 is 0x${computed.toString(16)} over its inflated bytes but 0x${claims.crc32.toString(16)} is recorded`,
        checked + 1,
      );
    checked += 1;
  }
  if (unchecked.length > 0)
    return {
      state: "unknown",
      entriesChecked: checked,
      detail: `${unchecked.length} ZIP entries were not CRC-verified: ${unchecked.slice(0, 3).join("; ")}${unchecked.length > 3 ? "; …" : ""}`,
    };
  return { state: "verified", entriesChecked: checked, detail: null };
};
