import {
  applyArtifactPatchInputSchema,
  artifactPatchApplyResultSchema,
  artifactPatchPlanSchema,
  artifactPatchVerifyResultSchema,
  planArtifactPatchInputSchema,
  verifyArtifactPatchInputSchema,
} from "../domain/artifactPatch.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";

/** Caller-directed artifact mutation contracts shared by CLI and MCP. */
export const ARTIFACT_PATCH_TOOL_CONTRACTS = [
  {
    name: "plan_artifact_patch",
    ...toolContractMetadata("plan_artifact_patch"),
    description:
      "Plan equal-length byte replacements against one local artifact without writing anything. Select each range by exact file offset with the bytes it must already contain, by a literal pattern that must match exactly once, or by a numbered occurrence; every selected byte is verified before a plan exists. Returns the resolved spans, the container framing (flat, ZIP or ASAR), every framing update such as a ZIP CRC-32, the resulting digest and a plan_digest that binds apply_artifact_patch to exactly these bytes. ZIP stored entries, ASAR file data and flat files are supported; compressed, encrypted, data-descriptor and integrity-declared entries are refused with a typed reason. Whole-file admission bounds the artifact at 512 MiB with 256 operations, 1 MiB per replacement and 4 MiB in total. The artifact is read only: no bytes are written and nothing is executed.",
    kind: "application",
    inputSchema: planArtifactPatchInputSchema,
    outputSchema: evidenceResultOf(artifactPatchPlanSchema),
    examples: [
      {
        title: "Plan one constant replacement by exact offset",
        input: {
          target_path: "/analysis/libapp.so",
          operations: [
            {
              match: {
                kind: "file_offset",
                offset: 4096,
                expected_hex: "00",
              },
              replacement_hex: "01",
              note: "force the enable flag",
            },
          ],
        },
      },
      {
        title: "Plan a unique pattern replacement inside a stored ZIP entry",
        input: {
          target_path: "/analysis/app.apk",
          operations: [
            {
              match: {
                kind: "unique_match",
                pattern_hex: "0a4d61726b6574",
              },
              replacement_hex: "0a4d61726b6574",
            },
          ],
        },
      },
    ],
  },
  {
    name: "apply_artifact_patch",
    ...toolContractMetadata("apply_artifact_patch"),
    description:
      "Apply verified artifact byte replacements to a copy by default, or to the target artifact itself only under explicit in-place authority. The artifact is re-read, every expected byte is re-verified against the current bytes, an optional plan_digest must still match, and the written artifact is re-read and verified byte-for-byte against the plan: SHA-256, every replaced region and the container framing. Copy mode writes output_path and never touches the target. In-place mode requires acknowledge_in_place and expected_target_sha256, refuses symbolic links, multiple hard links and framing hazards, and replaces the target with one rename after re-reading and re-identifying it. Reports both identities, applied operations, framing changes and limitations such as invalidated ZIP signatures, so callers can re-sign a patched APK, JAR or IPA before distribution. Equal-length replacement only; the artifact is never executed.",
    kind: "application",
    inputSchema: applyArtifactPatchInputSchema,
    outputSchema: evidenceResultOf(artifactPatchApplyResultSchema),
    examples: [
      {
        title: "Write a patched copy next to the target",
        input: {
          target_path: "/analysis/libapp.so",
          output_path: "/analysis/libapp.patched.so",
          operations: [
            {
              match: {
                kind: "file_offset",
                offset: 4096,
                expected_hex: "00",
              },
              replacement_hex: "01",
            },
          ],
        },
      },
      {
        title: "Replace one authorized target in place",
        input: {
          target_path: "/analysis/libapp.so",
          in_place: true,
          acknowledge_in_place: true,
          expected_target_sha256:
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          operations: [
            {
              match: {
                kind: "unique_match",
                pattern_hex: "1f2003d5",
              },
              replacement_hex: "1f2003d5",
            },
          ],
        },
      },
    ],
  },
  {
    name: "verify_artifact_patch",
    ...toolContractMetadata("verify_artifact_patch"),
    description:
      "Re-read one local artifact and report whether its bytes still match an expected SHA-256 and caller-supplied byte regions, together with container framing integrity: per-entry CRC-32 for ZIP stored entries and header/range validity for ASAR payloads. Read-only, so nothing is written and nothing is executed. Use it after apply_artifact_patch, after re-signing or repackaging, or on any copy whose exact bytes have to be confirmed.",
    kind: "application",
    inputSchema: verifyArtifactPatchInputSchema,
    outputSchema: evidenceResultOf(artifactPatchVerifyResultSchema),
    examples: [
      {
        title: "Verify one written copy against its region",
        input: {
          target_path: "/analysis/libapp.patched.so",
          expected_sha256:
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          regions: [
            {
              file_offset: 4096,
              expected_hex: "01",
            },
          ],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
