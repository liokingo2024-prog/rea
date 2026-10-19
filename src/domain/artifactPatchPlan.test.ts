import { createHash } from "node:crypto";
import { crc32, deflateRawSync } from "node:zlib";

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
  /** Raw general purpose flags; descriptor adds 0x0008 on top. */
  readonly flags?: number;
  /** Declared uncompressed size; defaults to the payload length. */
  readonly uncompressedBytes?: number;
  /** Declared CRC-32; defaults to the CRC-32 of the payload. */
  readonly crc32?: number;
  /** Record CRC-32 and sizes after the payload instead of in the local header. */
  readonly descriptor?: boolean;
}

/** Minimal store-only ZIP writer for exact-offset container tests. */
const zipArchive = (entries: readonly ZipEntry[]): Buffer => {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let localOffset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const method = entry.method ?? 0;
    const declaredCrc = entry.crc32 ?? crc32(entry.data);
    const declaredUncompressed = entry.uncompressedBytes ?? entry.data.length;
    const flags = (entry.flags ?? 0) | (entry.descriptor === true ? 0x0008 : 0);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    if (entry.descriptor !== true) {
      local.writeUInt32LE(declaredCrc, 14);
      local.writeUInt32LE(entry.data.length, 18);
      local.writeUInt32LE(declaredUncompressed, 22);
    }
    local.writeUInt16LE(name.length, 26);
    const descriptor = Buffer.alloc(16);
    if (entry.descriptor === true) {
      descriptor.writeUInt32LE(0x08074b50, 0);
      descriptor.writeUInt32LE(declaredCrc, 4);
      descriptor.writeUInt32LE(entry.data.length, 8);
      descriptor.writeUInt32LE(declaredUncompressed, 12);
    }
    locals.push(
      local,
      name,
      entry.data,
      ...(entry.descriptor === true ? [descriptor] : []),
    );
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(declaredCrc, 16);
    central.writeUInt32LE(entry.data.length, 20);
    central.writeUInt32LE(declaredUncompressed, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(localOffset, 42);
    centrals.push(central, name);
    localOffset +=
      30 +
      name.length +
      entry.data.length +
      (entry.descriptor === true ? descriptor.length : 0);
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

describe("verifyContainerIntegrity over ZIP containers", () => {
  const containerOf = (bytes: Buffer): ArtifactContainer => {
    const container = classifyArtifactContainer(bytes);
    if (!container.ok) throw new Error(container.error.detail);
    return container.value;
  };

  it("verifies stored members and deflate members from their own bytes", () => {
    const text = Buffer.from("FLAG=0\nnotes\n");
    const bytes = zipArchive([
      { name: "assets/config.txt", data: text },
      {
        name: "assets/app.js",
        data: deflateRawSync(text),
        method: 8,
        uncompressedBytes: text.length,
        crc32: crc32(text),
      },
    ]);
    const integrity = verifyContainerIntegrity(bytes, containerOf(bytes));
    expect(integrity.state).toBe("verified");
    expect(integrity.entriesChecked).toBe(2);
    expect(integrity.detail).toBeNull();
  });

  it("verifies members whose local header holds a data descriptor", () => {
    const text = Buffer.from("classes payload");
    const bytes = zipArchive([
      {
        name: "classes.dex",
        data: deflateRawSync(text),
        method: 8,
        uncompressedBytes: text.length,
        crc32: crc32(text),
        descriptor: true,
      },
    ]);
    const integrity = verifyContainerIntegrity(bytes, containerOf(bytes));
    expect(integrity.state).toBe("verified");
    expect(integrity.entriesChecked).toBe(1);
  });

  it("reports the entry whose stored bytes stop matching its CRC-32", () => {
    const bytes = zipArchive([
      { name: "res/raw/payload.bin", data: Buffer.from("ABCDEFGH") },
      { name: "res/raw/other.bin", data: Buffer.from("IJKLMNOP") },
    ]);
    const tampered = Buffer.from(bytes);
    tampered[30 + "res/raw/payload.bin".length + 3] = 0x5a;
    const integrity = verifyContainerIntegrity(tampered, containerOf(bytes));
    expect(integrity.state).toBe("mismatch");
    expect(integrity.detail).toContain("res/raw/payload.bin");
  });

  it("reports a local header that contradicts the central directory", () => {
    const bytes = zipArchive([{ name: "a.bin", data: Buffer.from("AAAA") }]);
    const tampered = Buffer.from(bytes);
    tampered.writeUInt32LE(0x11111111, 14);
    const integrity = verifyContainerIntegrity(tampered, containerOf(bytes));
    expect(integrity.state).toBe("mismatch");
    expect(integrity.detail).toContain("local header");
  });

  it("reports a member that is not a readable deflate stream", () => {
    const bytes = zipArchive([
      { name: "classes.dex", data: Buffer.from("not deflate"), method: 8 },
    ]);
    const integrity = verifyContainerIntegrity(bytes, containerOf(bytes));
    expect(integrity.state).toBe("mismatch");
    expect(integrity.detail).toContain("deflate stream");
  });

  it("stays unknown for members it cannot check instead of claiming verification", () => {
    const encrypted = zipArchive([
      { name: "assets/config.txt", data: Buffer.from("FLAG=0\n"), flags: 1 },
    ]);
    const encryptedIntegrity = verifyContainerIntegrity(
      encrypted,
      containerOf(encrypted),
    );
    expect(encryptedIntegrity.state).toBe("unknown");
    expect(encryptedIntegrity.detail).toContain("encrypted");

    const otherMethod = zipArchive([
      { name: "assets/config.txt", data: Buffer.from("FLAG=0\n"), method: 12 },
    ]);
    expect(
      verifyContainerIntegrity(otherMethod, containerOf(otherMethod)).state,
    ).toBe("unknown");
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
