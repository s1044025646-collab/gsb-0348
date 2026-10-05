import path from "node:path";

export const PROJECT_ROOT = path.resolve(process.cwd());

export const config = {
  dataDir: process.env.PCAP_DATA_DIR
    ? path.resolve(process.env.PCAP_DATA_DIR)
    : path.join(PROJECT_ROOT, "data"),
  maxFileSize: Number(process.env.PCAP_MAX_FILE_SIZE ?? 16 * 1024 * 1024),
  maxRecords: Number(process.env.PCAP_MAX_RECORDS ?? 100_000),
  defaultPort: Number(process.env.PCAP_PORT ?? 0), // 0 = 自动选择空闲端口
};

export function dbPath(): string {
  return path.join(config.dataDir, "pcap-inspect.db");
}
export function blobDir(): string {
  return path.join(config.dataDir, "blobs");
}

/** 校验目标路径位于项目目录内，防止越界扫描 */
export function resolveInsideProject(p: string): string {
  const abs = path.resolve(PROJECT_ROOT, p);
  const rel = path.relative(PROJECT_ROOT, abs);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error(`路径越出项目目录：${p}`);
  }
  return abs;
}
