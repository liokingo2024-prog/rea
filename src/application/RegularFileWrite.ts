import { createHash, randomUUID } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { lstat, open, realpath, rename, stat, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

/** The selected output path already exists and replacing it was not requested. */
export class RegularFileWriteExistsError extends Error {
  readonly code = "EEXIST";
  constructor(readonly path: string) {
    super(`Output file already exists: ${path}`);
    this.name = "RegularFileWriteExistsError";
  }
}

/** The selected path cannot receive written bytes as one regular file. */
export class RegularFileWriteTargetError extends Error {
  constructor(
    readonly path: string,
    readonly detail: string,
  ) {
    super(`Output path cannot be written: ${path} (${detail})`);
    this.name = "RegularFileWriteTargetError";
  }
}

/** The in-place target no longer matches the identity the caller authorized. */
export class RegularFileReplacementChangedError extends Error {
  readonly code = "ESTALE";
  constructor(
    readonly path: string,
    readonly detail: string,
  ) {
    super(`In-place target changed before replacement: ${path} (${detail})`);
    this.name = "RegularFileReplacementChangedError";
  }
}

export interface WrittenRegularFile {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
  /** Present after an in-place replacement, identifying the bytes it replaced. */
  readonly previous?: {
    readonly sha256: string;
    readonly bytes: number;
  };
}

const assertActive = (signal?: AbortSignal): void => {
  signal?.throwIfAborted();
};

/** Stage bytes beside their destination so publication is one rename. */
const stageOwnedFile = async (
  destination: string,
  bytes: Buffer,
  signal: AbortSignal | undefined,
): Promise<string> => {
  const staged = join(
    dirname(destination),
    `.${basename(destination)}.rea-patch-${randomUUID()}.tmp`,
  );
  let handle: FileHandle | undefined;
  let published = false;
  try {
    handle = await open(staged, "wx", 0o600);
    assertActive(signal);
    let written = 0;
    while (written < bytes.length) {
      const { bytesWritten } = await handle.write(
        bytes,
        written,
        bytes.length - written,
        written,
      );
      if (bytesWritten === 0)
        throw new RegularFileWriteTargetError(
          destination,
          "the staged write made no progress",
        );
      written += bytesWritten;
      assertActive(signal);
    }
    await handle.sync();
    published = true;
    return staged;
  } finally {
    await handle?.close().catch(() => undefined);
    if (!published) await unlink(staged).catch(() => undefined);
  }
};

const existingDestination = async (
  path: string,
): Promise<BigIntStats | undefined> =>
  lstat(path, { bigint: true }).catch((cause: unknown) => {
    if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw cause;
  });

/**
 * Write one owned output file atomically: canonical parent, absent path unless
 * replacement was requested, staged bytes in the destination directory, then a
 * single rename. Nothing is written when admission fails.
 */
export const writeRegularFileBytes = async (
  bytes: Buffer,
  path: string,
  overwrite: boolean,
  signal?: AbortSignal,
): Promise<WrittenRegularFile> => {
  const canonicalParent = await realpath(dirname(resolve(path)));
  const destination = resolve(canonicalParent, basename(path));
  const existing = await existingDestination(destination);
  if (existing !== undefined) {
    if (existing.isSymbolicLink())
      throw new RegularFileWriteTargetError(
        destination,
        "the existing path is a symbolic link",
      );
    if (!existing.isFile())
      throw new RegularFileWriteTargetError(
        destination,
        "the existing path is not a regular file",
      );
    if (!overwrite) throw new RegularFileWriteExistsError(destination);
  }
  const staged = await stageOwnedFile(destination, bytes, signal);
  try {
    assertActive(signal);
    await rename(staged, destination);
  } catch (cause: unknown) {
    await unlink(staged).catch(() => undefined);
    throw cause;
  }
  return {
    path: destination,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.length,
  };
};

const refusalForIdentity = (metadata: BigIntStats): string | null =>
  metadata.isSymbolicLink()
    ? "the target is a symbolic link"
    : !metadata.isFile()
      ? "the target is not a regular file"
      : metadata.nlink > 1n
        ? `the target has ${metadata.nlink} hard links, so replacing one name would not update the others`
        : null;

interface TargetRead {
  readonly bytes: Buffer;
  readonly identity: BigIntStats;
}

const readTarget = async (
  path: string,
  maxBytes: number,
): Promise<TargetRead> => {
  const handle = await open(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const identity = await handle.stat({ bigint: true });
    const refusal = refusalForIdentity(identity);
    if (refusal !== null) throw new RegularFileWriteTargetError(path, refusal);
    if (identity.size > BigInt(maxBytes))
      throw new RegularFileReplacementChangedError(
        path,
        `the target is ${identity.size} bytes, beyond the ${maxBytes}-byte admission bound`,
      );
    const bytes = await handle.readFile();
    if (BigInt(bytes.length) !== identity.size)
      throw new RegularFileReplacementChangedError(
        path,
        "the target changed while it was re-read for authorization",
      );
    return { bytes, identity };
  } finally {
    await handle.close();
  }
};

const sameIdentity = (left: BigIntStats, right: BigIntStats): boolean =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.size === right.size &&
  left.mtimeNs === right.mtimeNs &&
  left.ctimeNs === right.ctimeNs;

/**
 * Replace one authorized target in place. The caller supplies the digest it
 * authorized; the target is re-read and must still match that digest, its
 * descriptor identity is re-checked after staging, and the previous bytes are
 * reported so the caller can attribute exactly what was replaced.
 */
export const replaceRegularFileBytesInPlace = async (
  bytes: Buffer,
  path: string,
  expectedSha256: string,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<WrittenRegularFile> => {
  const canonicalParent = await realpath(dirname(resolve(path)));
  const target = resolve(canonicalParent, basename(path));
  const admitted = await readTarget(target, maxBytes);
  const currentSha256 = createHash("sha256")
    .update(admitted.bytes)
    .digest("hex");
  if (currentSha256 !== expectedSha256)
    throw new RegularFileReplacementChangedError(
      target,
      `the target sha256 is ${currentSha256}, not the authorized ${expectedSha256}`,
    );
  assertActive(signal);
  const staged = await stageOwnedFile(target, bytes, signal);
  try {
    const confirmed = await stat(target, { bigint: true });
    if (!sameIdentity(admitted.identity, confirmed)) {
      await unlink(staged).catch(() => undefined);
      throw new RegularFileReplacementChangedError(
        target,
        "the target identity changed between authorization and replacement",
      );
    }
    assertActive(signal);
    await rename(staged, target);
  } catch (cause: unknown) {
    await unlink(staged).catch(() => undefined);
    throw cause;
  }
  return {
    path: target,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    bytes: bytes.length,
    previous: { sha256: currentSha256, bytes: admitted.bytes.length },
  };
};
