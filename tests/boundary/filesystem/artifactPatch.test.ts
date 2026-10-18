import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { crc32 } from "node:zlib";

import { describe, expect, it } from "vitest";

import {
  applyArtifactPatch,
  planArtifactPatch,
  verifyArtifactPatch,
} from "../../../src/application/ArtifactPatchService.js";
import { ArtifactPatchError } from "../../../src/domain/artifactPatchError.js";
import { AnalysisInputError } from "../../../src/domain/analysisErrorCore.js";
import type { Evidence } from "../../../src/domain/evidence.js";
import { withArtifactResourceScope } from "../../fixtures/artifactInventory.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const sha256 = (bytes: Buffer): string =>
  createHash("sha256").update(bytes).digest("hex");

interface PlanResult {
  readonly plan_digest: string;
  readonly resulting: { readonly sha256: string; readonly bytes: number };
  readonly target: { readonly sha256: string };
  readonly container: { readonly kind: string };
}

interface ApplyResult {
  readonly plan_digest: string;
  readonly mode: string;
  readonly artifact: { readonly path: string; readonly sha256: string };
  readonly container: { readonly kind: string };
  readonly verification: {
    readonly state: string;
    readonly regions_verified: number;
  };
  readonly limitations: readonly string[];
}

interface VerifyResult {
  readonly digest: { readonly state: string; readonly actual_sha256: string };
  readonly regions: readonly {
    readonly state: string;
    readonly expected_hex: string;
    readonly actual_hex: string;
  }[];
  readonly container: {
    readonly kind: string;
    readonly integrity: string;
    readonly entries_checked: number;
  };
}

const normalized = <Value>(evidence: Evidence): Value =>
  evidence.normalized_result as Value;

const replaceOffset = (
  offset: number,
  expectedHex: string,
  replacementHex: string,
) => ({
  match: { kind: "file_offset" as const, offset, expected_hex: expectedHex },
  replacement_hex: replacementHex,
});

/** Store-only ZIP writer so container framing is checked end to end. */
const zipArchive = (name: string, data: Buffer): Buffer => {
  const nameBytes = Buffer.from(name, "utf8");
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt32LE(crc32(data), 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(nameBytes.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt32LE(crc32(data), 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(nameBytes.length, 28);
  central.writeUInt32LE(0, 42);
  const centralBytes = Buffer.concat([central, nameBytes]);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(30 + nameBytes.length + data.length, 16);
  return Buffer.concat([local, nameBytes, data, centralBytes, end]);
};

describe("artifact patch planning and copies", () => {
  it("plans and writes one verified copy without touching the target", async () => {
    const directory = await createTestTempDirectory("rea-artifact-patch-");
    const target = join(directory, "target.bin");
    const output = join(directory, "patched.bin");
    await writeFile(target, Buffer.from("ABCDEFGH", "utf8"));
    await withArtifactResourceScope(async (resources) => {
      const operation = replaceOffset(2, "434445", "78797a");
      const planned = await planArtifactPatch(
        { target_path: target, operations: [operation] },
        resources,
      );
      expect(planned.ok).toBe(true);
      if (!planned.ok) return;
      const plan = normalized<PlanResult>(planned.value);
      expect(plan.container.kind).toBe("flat");
      expect(plan.resulting.bytes).toBe(8);

      const applied = await applyArtifactPatch(
        {
          target_path: target,
          output_path: output,
          plan_digest: plan.plan_digest,
          operations: [operation],
        },
        resources,
      );
      expect(applied.ok).toBe(true);
      if (!applied.ok) return;
      const result = normalized<ApplyResult>(applied.value);
      expect(result.mode).toBe("copy");
      expect(result.artifact.path).toBe(output);
      expect(result.artifact.sha256).toBe(plan.resulting.sha256);
      expect(result.verification).toEqual({
        state: "verified",
        regions_verified: 1,
        expected_sha256: plan.resulting.sha256,
      });
      expect(result.limitations.join(" ")).toContain("left unchanged");
      expect(await readFile(output, "utf8")).toBe("ABxyzFGH");
      expect(await readFile(target, "utf8")).toBe("ABCDEFGH");

      const verified = await verifyArtifactPatch(
        {
          target_path: output,
          expected_sha256: plan.resulting.sha256,
          regions: [{ file_offset: 2, expected_hex: "78797a" }],
        },
        resources,
      );
      expect(verified.ok).toBe(true);
      if (!verified.ok) return;
      const verification = normalized<VerifyResult>(verified.value);
      expect(verification.digest.state).toBe("matches");
      expect(verification.regions[0]?.state).toBe("matches");
    });
  });

  it("refuses an existing output path unless replacement was requested", async () => {
    const directory = await createTestTempDirectory("rea-artifact-patch-");
    const target = join(directory, "target.bin");
    const output = join(directory, "patched.bin");
    await writeFile(target, Buffer.from("ABCDEFGH", "utf8"));
    await writeFile(output, Buffer.from("occupied", "utf8"));
    await withArtifactResourceScope(async (resources) => {
      const refused = await applyArtifactPatch(
        {
          target_path: target,
          output_path: output,
          operations: [replaceOffset(2, "434445", "78797a")],
        },
        resources,
      );
      expect(refused.ok).toBe(false);
      if (refused.ok) return;
      expect(refused.error).toBeInstanceOf(AnalysisInputError);
      const issue = (refused.error as AnalysisInputError).issues[0];
      expect(issue?.path).toEqual(["output_path"]);
      expect(issue?.message).toContain("already exists");
      expect(await readFile(output, "utf8")).toBe("occupied");

      const replaced = await applyArtifactPatch(
        {
          target_path: target,
          output_path: output,
          overwrite: true,
          operations: [replaceOffset(2, "434445", "78797a")],
        },
        resources,
      );
      expect(replaced.ok).toBe(true);
      if (!replaced.ok) return;
      expect(await readFile(output, "utf8")).toBe("ABxyzFGH");
    });
  });

  it("reports a tampered copy as a digest mismatch and keeps regions exact", async () => {
    const directory = await createTestTempDirectory("rea-artifact-patch-");
    const target = join(directory, "target.bin");
    const output = join(directory, "patched.bin");
    await writeFile(target, Buffer.from("ABCDEFGH", "utf8"));
    await withArtifactResourceScope(async (resources) => {
      const applied = await applyArtifactPatch(
        {
          target_path: target,
          output_path: output,
          operations: [replaceOffset(2, "434445", "78797a")],
        },
        resources,
      );
      expect(applied.ok).toBe(true);
      if (!applied.ok) return;
      const expected = normalized<ApplyResult>(applied.value).artifact.sha256;
      await writeFile(output, Buffer.from("ABxyzFGJ", "utf8"));
      const verified = await verifyArtifactPatch(
        {
          target_path: output,
          expected_sha256: expected,
          regions: [{ file_offset: 2, expected_hex: "78797a" }],
        },
        resources,
      );
      expect(verified.ok).toBe(true);
      if (!verified.ok) return;
      const verification = normalized<VerifyResult>(verified.value);
      expect(verification.digest.state).toBe("mismatch");
      expect(verification.digest.actual_sha256).toBe(
        sha256(Buffer.from("ABxyzFGJ", "utf8")),
      );
      expect(verification.regions[0]?.state).toBe("matches");
    });
  });
});

describe("artifact patch in-place authority", () => {
  it("refuses replacement without explicit authority", async () => {
    const directory = await createTestTempDirectory("rea-artifact-patch-");
    const target = join(directory, "target.bin");
    await writeFile(target, Buffer.from("ABCDEFGH", "utf8"));
    await withArtifactResourceScope(async (resources) => {
      const refused = await applyArtifactPatch(
        {
          target_path: target,
          in_place: true,
          operations: [replaceOffset(2, "434445", "78797a")],
        },
        resources,
      );
      expect(refused.ok).toBe(false);
      if (refused.ok) return;
      expect(refused.error).toBeInstanceOf(ArtifactPatchError);
      expect((refused.error as ArtifactPatchError).reason).toBe(
        "authority_required",
      );
      expect(await readFile(target, "utf8")).toBe("ABCDEFGH");
    });
  });

  it("replaces the authorized target and reports the previous bytes", async () => {
    const directory = await createTestTempDirectory("rea-artifact-patch-");
    const target = join(directory, "target.bin");
    const original = Buffer.from("ABCDEFGH", "utf8");
    await writeFile(target, original);
    await withArtifactResourceScope(async (resources) => {
      const applied = await applyArtifactPatch(
        {
          target_path: target,
          in_place: true,
          acknowledge_in_place: true,
          expected_target_sha256: sha256(original),
          operations: [replaceOffset(2, "434445", "78797a")],
        },
        resources,
      );
      expect(applied.ok).toBe(true);
      if (!applied.ok) return;
      const result = normalized<ApplyResult>(applied.value);
      expect(result.mode).toBe("in_place");
      expect(await readFile(target, "utf8")).toBe("ABxyzFGH");
      expect(result.limitations.join(" ")).toContain("No backup copy");
    });
  });

  it("refuses replacement when the authorized digest moved", async () => {
    const directory = await createTestTempDirectory("rea-artifact-patch-");
    const target = join(directory, "target.bin");
    await writeFile(target, Buffer.from("ABCDEFGH", "utf8"));
    await withArtifactResourceScope(async (resources) => {
      const refused = await applyArtifactPatch(
        {
          target_path: target,
          in_place: true,
          acknowledge_in_place: true,
          expected_target_sha256: sha256(Buffer.from("znvutvqn", "utf8")),
          operations: [replaceOffset(2, "434445", "78797a")],
        },
        resources,
      );
      expect(refused.ok).toBe(false);
      if (refused.ok) return;
      expect((refused.error as ArtifactPatchError).reason).toBe(
        "authority_required",
      );
      expect(await readFile(target, "utf8")).toBe("ABCDEFGH");
    });
  });
});

describe("artifact patch selection refusals", () => {
  it("refuses a plan whose expected bytes are absent from the artifact", async () => {
    const directory = await createTestTempDirectory("rea-artifact-patch-");
    const target = join(directory, "target.bin");
    await writeFile(target, Buffer.from("ABCDEFGH", "utf8"));
    await withArtifactResourceScope(async (resources) => {
      const refused = await planArtifactPatch(
        {
          target_path: target,
          operations: [replaceOffset(2, "7a7a7a", "78797a")],
        },
        resources,
      );
      expect(refused.ok).toBe(false);
      if (refused.ok) return;
      expect(refused.error).toBeInstanceOf(ArtifactPatchError);
      expect((refused.error as ArtifactPatchError).reason).toBe(
        "expected_bytes_mismatch",
      );
    });
  });
});

describe("artifact patch containers", () => {
  it("patches a stored ZIP entry and keeps framing valid", async () => {
    const directory = await createTestTempDirectory("rea-artifact-patch-");
    const target = join(directory, "app.apk");
    const output = join(directory, "app.patched.apk");
    const dataOffset = 30 + "assets/config.txt".length;
    await writeFile(
      target,
      zipArchive("assets/config.txt", Buffer.from("FLAG=0\nnotes\n")),
    );
    await withArtifactResourceScope(async (resources) => {
      const applied = await applyArtifactPatch(
        {
          target_path: target,
          output_path: output,
          operations: [replaceOffset(dataOffset + 5, "30", "31")],
        },
        resources,
      );
      expect(applied.ok).toBe(true);
      if (!applied.ok) return;
      const result = normalized<ApplyResult>(applied.value);
      expect(result.container.kind).toBe("zip");
      expect(result.limitations.join(" ")).toContain("re-signed");

      const verified = await verifyArtifactPatch(
        {
          target_path: output,
          regions: [{ file_offset: dataOffset + 5, expected_hex: "31" }],
        },
        resources,
      );
      expect(verified.ok).toBe(true);
      if (!verified.ok) return;
      const verification = normalized<VerifyResult>(verified.value);
      expect(verification.container).toEqual({
        kind: "zip",
        integrity: "verified",
        entries_checked: 1,
        limitations: [],
      });
      expect(await readFile(target, "utf8")).toContain("FLAG=0");
    });
  });
});
