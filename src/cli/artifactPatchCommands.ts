import { Cli, z } from "incur";

import {
  applyArtifactPatch,
  planArtifactPatch,
  verifyArtifactPatch,
} from "../application/ArtifactPatchService.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { parseCliJsonInput } from "../cliJsonInput.js";
import { logCliCommand } from "../cliLogging.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import {
  applyArtifactPatchInputSchema,
  planArtifactPatchInputSchema,
  verifyArtifactPatchInputSchema,
  type ApplyArtifactPatchInput,
  type PlanArtifactPatchInput,
  type VerifyArtifactPatchInput,
} from "../domain/artifactPatch.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Evidence } from "../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { Result } from "../domain/result.js";
import type { Logger } from "pino";

const PROVIDER_ID = "rea-artifact-patch";

type PatchInput =
  | PlanArtifactPatchInput
  | ApplyArtifactPatchInput
  | VerifyArtifactPatchInput;

/**
 * Register one artifact mutation command. MCP and CLI share the exact same
 * input schema, so a plan produced for one adapter validates for the other.
 */
const registerPatchCommand = <Schema extends z.ZodType<PatchInput>>({
  cli,
  logger,
  name,
  description,
  inputSchema,
  failureMessage,
  operation,
}: {
  readonly cli: ReturnType<typeof Cli.create>;
  readonly logger: Logger;
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Schema;
  readonly failureMessage: string;
  readonly operation: (
    input: PatchInput,
    resources: ArtifactResourceScope,
  ) => Promise<Result<Evidence, AnalysisError>>;
}): void => {
  cli.command(name, {
    description,
    args: z.object({
      inputJson: z
        .string()
        .describe(
          "Inline workflow JSON or a JSON file path matching the corresponding MCP tool input",
        ),
    }),
    run: ({ args }) =>
      logCliCommand(logger, name, async () => {
        const requested = await parseCliJsonInput(args.inputJson, name);
        if (!requested.ok) return requested.error;
        const parsed = inputSchema.safeParse(requested.value);
        if (!parsed.success)
          return {
            error: failureMessage,
            ...projectAnalysisError(
              analysisInputErrorFromIssues(
                name,
                parsed.error.issues,
                requested.value,
              ),
            ),
          };
        const resources = new ArtifactResourceScope();
        const result = await operation(parsed.data, resources);
        try {
          await resources.close();
        } catch (cause: unknown) {
          const cleanup = ArtifactReaderFailure.cleanupObservation(
            cause,
            "Artifact mutation resources",
          );
          const failure = new ProviderCleanupError(
            PROVIDER_ID,
            cleanup.resources,
            { reason: cleanup.reason },
            { cause, operation: name },
          );
          const error = result.ok
            ? failure
            : analysisErrorWithCleanupFailure(result.error, failure, name);
          return {
            error: failureMessage,
            ...projectAnalysisError(error),
          };
        }
        return result.ok
          ? result.value
          : {
              error: failureMessage,
              ...projectAnalysisError(result.error),
            };
      }),
  });
};

/** Register the shared artifact mutation workflows on the one-shot CLI. */
export const registerArtifactPatchCommands = (
  cli: ReturnType<typeof Cli.create>,
  logger: Logger,
): void => {
  registerPatchCommand({
    cli,
    logger,
    name: CLI_COMMANDS.planArtifactPatch,
    description:
      "Plan verified equal-length byte replacements for a local artifact without writing anything",
    inputSchema: planArtifactPatchInputSchema,
    failureMessage: "Artifact patch planning failed",
    operation: (input, resources) => planArtifactPatch(input, resources, {}),
  });
  registerPatchCommand({
    cli,
    logger,
    name: CLI_COMMANDS.applyArtifactPatch,
    description:
      "Write a patched artifact copy, or replace the target under explicit in-place authority",
    inputSchema: applyArtifactPatchInputSchema,
    failureMessage: "Artifact patch apply failed",
    operation: (input, resources) => applyArtifactPatch(input, resources, {}),
  });
  registerPatchCommand({
    cli,
    logger,
    name: CLI_COMMANDS.verifyArtifactPatch,
    description:
      "Verify artifact bytes, regions and container framing without writing anything",
    inputSchema: verifyArtifactPatchInputSchema,
    failureMessage: "Artifact patch verification failed",
    operation: (input, resources) => verifyArtifactPatch(input, resources, {}),
  });
};
