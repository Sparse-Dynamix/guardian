import { createWriteStream } from "node:fs";
import path from "node:path";
import { TarArchive, ZipArchive } from "archiver";

function packDirectory(
  archive: TarArchive | ZipArchive,
  sourceDir: string,
  destPath: string,
  rootName: string,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const output = createWriteStream(destPath);
    output.on("close", () => resolve());
    output.on("error", reject);
    archive.on("error", reject);
    archive.pipe(output);
    archive.directory(sourceDir, rootName);
    archive.finalize();
  });
}

export async function packZip(
  sourceDir: string,
  destPath: string,
  rootName: string,
): Promise<void> {
  await packDirectory(
    new ZipArchive({ zlib: { level: 9 } }),
    sourceDir,
    destPath,
    rootName,
  );
}

export async function packTarGz(
  sourceDir: string,
  destPath: string,
  rootName: string,
): Promise<void> {
  await packDirectory(
    new TarArchive({ gzip: true, gzipOptions: { level: 9 } }),
    sourceDir,
    destPath,
    rootName,
  );
}

export function archiveRootName(stagingDir: string): string {
  return path.basename(stagingDir);
}
