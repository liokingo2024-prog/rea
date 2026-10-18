import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { ArtifactPatchOperation } from "../domain/artifactPatchError.js";
import {
  applyArtifactPatch,
  planArtifactPatch,
  verifyArtifactPatch,
} from "../application/ArtifactPatchService.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import {
  createContractToolHandler,
  type ContractToolService,
} from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

const artifactPatchService = (
  resources: ArtifactResourceScope,
): ContractToolService<ArtifactPatchOperation> => ({
  execute: (operation, input, options) => {
    switch (operation) {
      case "plan_artifact_patch":
        return planArtifactPatch(input, resources, options);
      case "apply_artifact_patch":
        return applyArtifactPatch(input, resources, options);
      case "verify_artifact_patch":
        return verifyArtifactPatch(input, resources, options);
      default:
        throw new TypeError(`Unhandled artifact patch operation: ${operation}`);
    }
  },
});

/** Bind caller-directed artifact mutation to its exact named contracts. */
export const registerArtifactPatchTools = (
  server: EvidenceMcpServer,
  options: {
    readonly logger: Logger;
    readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
    readonly artifactResources: ArtifactResourceScope;
    readonly withAdmittedAnalysis?: WithAdmittedAnalysis;
  },
): void => {
  const handler = createContractToolHandler(
    server,
    artifactPatchService(options.artifactResources),
    options.logger,
    options.recordEvidence,
    options.withAdmittedAnalysis,
  );
  for (const contract of [
    toolContract("plan_artifact_patch"),
    toolContract("apply_artifact_patch"),
    toolContract("verify_artifact_patch"),
  ] as const) {
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
