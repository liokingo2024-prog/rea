import { createHash } from "node:crypto";
import { crc32 } from "node:zlib";

import { describe, expect, it } from "vitest";

import type { ArtifactPatchOperationInput } from "./artifactPatch.js";
import {
  classifyArtifactContainer,
  verifyContainerIntegrity,
  type ArtifactContainer,
} from "./artifactPatchContainer.js";
import { planArtifactPatch } from "./artifactPatchPlan.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

const flatOperation = (
  offset: number,
  expectedHex: string,
  replacementHex: string,
): ArtifactPatchOperationInput => ({
  match: { kind: "file_offset", offset, expected_hex: expectedHex },
  replacement_hex: replacementHex,
});

const plan = (
  bytes: Buffer,
  operations: readonly ArtifactPatchOperationInput[],
) => planArtifactPatch(bytes, { targetSha256: sha256(bytes), operations });

interface ZipEntry {
  readonly name: string;
  readonly data: Buffer;
  /** Overrides the declared method; the stored payload is unchanged. */
  readonly method?: number;
}

/** Minimal store-only ZIP writer for exact-offset container tests. */
const zipArchive = (entries: readonly ZipEntry[]): Buffer => {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(entry.method ?? 0, 8);
    local.writeUInt32LE(crc32(entry.data), 14);
    local.writeUInt32LE(entry.data.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, entry.data);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(entry.method ?? 0, 10);
    central.writeUInt32LE(crc32(entry.data), 16);
    central.writeUInt32LE(entry.data.length, 20);
    central.writeUInt32LE(entry.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(localOffset, 42);
    centrals.push(central, name);
    localOffset += 30 + name.length + entry.data.length;
  }
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...locals, centralBytes, end]);
};

interface AsarEntry {
  readonly name: string;
  readonly data: Buffer;
  readonly integrity?: boolean;
}

/** Minimal ASAR writer matching the pickled header layout asar produces. */
const asarArchive = (
  entries: readonly AsarEntry[],
): { readonly bytes: Buffer; readonly headerEnd: number } => {
  const files: Record<string, unknown> = {};
  let offset = 0;
  for (const entry of entries) {
    files[entry.name] = {
      size: entry.data.length,
      offset: String(offset),
      ...(entry.integrity === true
        ? {
            integrity: {
              algorithm: "SHA256",
              hash: "deadbeef",
              blockSize: 4194304,
            },
          }
        : {}),
    };
    offset += entry.data.length;
  }
  const json = Buffer.from(JSON.stringify({ files }), "utf8");
  const padding = (4 - (json.length % 4)) % 4;
  const payloadBytes = 4 + json.length + padding;
  const headerPickle = Buffer.alloc(4 + payloadBytes);
  headerPickle.writeUInt32LE(payloadBytes, 0);
  headerPickle.writeUInt32LE(json.length, 4);
  json.copy(headerPickle, 8);
  const archiveHeader = Buffer.alloc(8);
  archiveHeader.writeUInt32LE(4, 0);
  archiveHeader.writeUInt32LE(headerPickle.length, 4);
  return {
    bytes: Buffer.concat([
      archiveHeader,
      headerPickle,
      ...entries.map(({ data }) => data),
    ]),
    headerEnd: 8 + headerPickle.length,
  };
};

describe("planArtifactPatch", () => {
  it("replaces verified bytes at an exact offset and predicts the digest", () => {
    const bytes = Buffer.from("REA-0000-alpha-beta", "utf8");
    const result = plan(bytes, [flatOperation(4, "30303030", "31313131")]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const [operation] = result.value.operations;
    expect(operation?.fileOffset).toBe(4);
    expect(operation?.bytes).toBe(4);
    expect(operation?.containerEntry).toBeNull();
    expect(result.value.patchedBytes.toString("utf8")).toBe(
      "REA-1111-alpha-beta",
    );
    expect(result.value.resultingSha256).toBe(
      sha256(Buffer.from("REA-1111-alpha-beta", "utf8")),
    );
    expect(result.value.changes).toHaveLength(1);
    expect(result.value.changes[0]?.kind).toBe("byte_range");
    expect(result.value.limitations.join(" ")).toContain("equal-length");
  });

  it("refuses a replacement whose length differs from the selected range", () => {
    const result = plan(Buffer.from("abcdefgh", "utf8"), [
      flatOperation(2, "636465", "7879"),
    ]);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.reason).toBe("invalid_input");
    expect(result.error.detail).toContain("replacement");
  });

  it("refuses bytes that are not the bytes the operation expects", () => {
    const result = plan(Buffer.from("abcdefgh", "utf8"), [
      flatOperation(2, "7a7a7a", "78797a"),
    ]);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.reason).toBe("expected_bytes_mismatch");
  });

  it("refuses an ambiguous pattern and resolves a numbered occurrence", () => {
    const bytes = Buffer.from("deadbeef-deadbeef", "utf8");
    const ambiguous = plan(bytes, [
      {
        match: { kind: "unique_match", pattern_hex: "6465616462656566" },
        replacement_hex: "1111111111111111",
      },
    ]);
    expect(ambiguous.ok).toBe(false);
    if (ambiguous.ok) return;
    expect(ambiguous.error.reason).toBe("match_unresolved");

    const second = plan(bytes, [
      {
        match: {
          kind: "nth_match",
          pattern_hex: "6465616462656566",
          occurrence: 2,
        },
        replacement_hex: "1111111111111111",
      },
    ]);
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.value.operations[0]?.fileOffset).toBe(9);
  });

  it("refuses operations that replace overlapping ranges", () => {
    const result = plan(Buffer.from("abcdefgh", "utf8"), [
      flatOperation(1, "6263", "7879"),
      flatOperation(2, "6364", "797a"),
    ]);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.reason).toBe("overlap");
  });

  it("binds a stable plan digest to the exact operations", () => {
    const bytes = Buffer.from("abcdefgh", "utf8");
    const first = plan(bytes, [flatOperation(1, "6263", "7879")]);
    const second = plan(bytes, [flatOperation(1, "6263", "7879")]);
    const different = plan(bytes, [flatOperation(1, "6263", "797a")]);
    expect(first.ok && second.ok && different.ok).toBe(true);
    if (!first.ok || !second.ok || !different.ok) return;
    expect(first.value.planDigest).toBe(second.value.planDigest);
    expect(first.value.planDigest).not.toBe(different.value.planDigest);
  });
});

describe("planArtifactPatch over ZIP containers", () => {
  const archive = (): {
    readonly bytes: Buffer;
    readonly dataOffset: number;
    readonly container: ArtifactContainer;
  } => {
    const bytes = zipArchive([
      { name: "assets/config.txt", data: Buffer.from("FLAG=0\nnotes\n") },
    ]);
    const container = classifyArtifactContainer(bytes);
    if (!container.ok) throw new Error(container.error.detail);
    return {
      bytes,
      dataOffset: 30 + "assets/config.txt".length,
      container: container.value,
    };
  };

  it("updates the stored CRC-32 in both records and verifies framing", () => {
    const { bytes, dataOffset, container } = archive();
    const result = plan(bytes, [flatOperation(dataOffset + 5, "30", "31")]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const [operation] = result.value.operations;
    expect(operation?.containerEntry).toBe("assets/config.txt");
    const crcChanges = result.value.changes.filter(
      (change) => change.kind === "zip_crc32",
    );
    expect(crcChanges).toHaveLength(2);
    expect(
      verifyContainerIntegrity(result.value.patchedBytes, container).state,
    ).toBe("verified");
    expect(verifyContainerIntegrity(bytes, container).state).toBe("verified");
  });

  it("refuses compressed entries and framing ranges", () => {
    const { bytes, dataOffset } = archive();
    const compressed = zipArchive([
      {
        name: "assets/config.txt",
        data: Buffer.from("FLAG=0\nnotes\n"),
        method: 8,
      },
    ]);
    const onCompressed = plan(compressed, [
      flatOperation(dataOffset + 5, "30", "31"),
    ]);
    expect(onCompressed.ok).toBe(false);
    if (onCompressed.ok) return;
    expect(onCompressed.error.reason).toBe("container_unsupported");
    expect(onCompressed.error.detail).toContain("compression method");

    const inFraming = plan(bytes, [flatOperation(6, "00", "01")]);
    expect(inFraming.ok).toBe(false);
    if (inFraming.ok) return;
    expect(inFraming.error.reason).toBe("container_unsupported");
  });
});

describe("planArtifactPatch over ASAR containers", () => {
  it("patches modeled file data and refuses header ranges", () => {
    const { bytes, headerEnd } = asarArchive([
      { name: "app.js", data: Buffer.from("const flag=false;\n") },
    ]);
    const replaced = plan(bytes, [
      flatOperation(headerEnd + 11, "66616c7365", "7472756520"),
    ]);
    expect(replaced.ok).toBe(true);
    if (!replaced.ok) return;
    expect(replaced.value.operations[0]?.containerEntry).toBe("app.js");

    const headerByte = bytes.subarray(9, 10).toString("hex");
    const inHeader = plan(bytes, [
      flatOperation(9, headerByte, headerByte === "01" ? "02" : "01"),
    ]);
    expect(inHeader.ok).toBe(false);
    if (inHeader.ok) return;
    expect(inHeader.error.reason).toBe("container_unsupported");
  });

  it("refuses entries that declare integrity metadata", () => {
    const { bytes, headerEnd } = asarArchive([
      {
        name: "app.js",
        data: Buffer.from("const flag=false;\n"),
        integrity: true,
      },
    ]);
    const result = plan(bytes, [
      flatOperation(headerEnd + 11, "66616c7365", "7472756520"),
    ]);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.reason).toBe("container_unsupported");
    expect(result.error.detail).toContain("integrity");
  });
});
