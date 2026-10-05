// 业务逻辑：导入、校验、查询、过滤、报告。
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { config, resolveInsideProject, blobDir, PROJECT_ROOT } from "./config.js";
import { ApiError } from "./errors.js";
import { parsePcap, timestampToNanoString, PcapFormatError, type SubsecPrecision } from "./pcap/parser.js";
import { decodeRecord, type DecodeResult } from "./pcap/decode.js";
import { getDb, type FileRow, type RecordRow, type DiagnosticRow } from "./store.js";

function sha256(buf: Buffer): string {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

export function getLimits() {
  return {
    maxFileSize: config.maxFileSize,
    maxRecords: config.maxRecords,
    supportedVersions: ["2.4"],
    supportedLinktypes: { 1: "Ethernet" },
    supportedProtocols: ["Ethernet", "IPv4(无分片)", "UDP"],
    byteOrders: ["little-endian", "big-endian"],
    subsecPrecisions: ["microsecond", "nanosecond"],
    notes: [
      "仅读取项目目录内已存在的文件，不捕获网卡、不发送数据包",
      "不支持 PCAPNG / TCP 重组 / 外部协议识别库",
      "记录顺序保持文件原样，不因时间戳倒退而排序",
    ],
  };
}

function readSourceFile(inputPath: string): { abs: string; buf: Buffer } {
  let abs: string;
  try {
    abs = resolveInsideProject(inputPath);
  } catch {
    throw new ApiError("PATH_OUT_OF_SCOPE", `只允许读取项目目录内的文件：${inputPath}`, 403);
  }
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
    throw new ApiError("NOT_FOUND", `文件不存在：${inputPath}`, 404);
  }
  const size = fs.statSync(abs).size;
  if (size > config.maxFileSize) {
    throw new ApiError("LIMIT_EXCEEDED", `文件 ${size} 字节超过上限 ${config.maxFileSize}`, 413);
  }
  return { abs, buf: fs.readFileSync(abs) };
}

export interface ImportResult {
  fileId: number;
  status: "ok" | "partial";
  sha256: string;
  recordCount: number;
  diagnosticCount: number;
  truncated: boolean;
}

export function importFile(inputPath: string): ImportResult {
  const { abs, buf } = readSourceFile(inputPath);
  let parsed;
  try {
    parsed = parsePcap(buf, config.maxRecords);
  } catch (e) {
    if (e instanceof PcapFormatError) {
      // 导入失败不登记为有效抓包
      throw new ApiError("UNSUPPORTED_FORMAT", `导入失败：${e.message}`, 422, { offset: e.offset });
    }
    throw e;
  }
  const hash = sha256(buf);
  fs.mkdirSync(blobDir(), { recursive: true });
  const blobPath = path.join(blobDir(), `${hash}.pcap`);
  if (!fs.existsSync(blobPath)) {
    fs.copyFileSync(abs, blobPath); // 项目内固定副本，后续替换原文件不影响旧偏移
  }
  const db = getDb();
  const status = parsed.truncated || parsed.diagnostics.length > 0 ? "partial" : "ok";
  const relOriginal = path.relative(PROJECT_ROOT, abs);
  const relBlob = path.relative(PROJECT_ROOT, blobPath);
  const insertFile = db.prepare(
    `INSERT INTO files (original_path, blob_path, sha256, size, byte_order, precision, version, snaplen, status, record_count, diagnostic_count, imported_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const info = insertFile.run(
    relOriginal, relBlob, hash, buf.length,
    parsed.header.byteOrder, parsed.header.precision,
    `${parsed.header.versionMajor}.${parsed.header.versionMinor}`,
    parsed.header.snaplen, status, parsed.records.length, parsed.diagnostics.length,
    new Date().toISOString()
  );
  const fileId = Number(info.lastInsertRowid);
  const insertRec = db.prepare(
    `INSERT INTO records (file_id, idx, ts_sec, ts_subsec, incl_len, orig_len, header_offset, data_offset,
      decode_status, decode_reason, eth_src, eth_dst, ip_src, ip_dst, udp_sport, udp_dport, udp_len, digest)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const insertDiag = db.prepare(
    `INSERT INTO diagnostics (file_id, record_idx, offset, code, message) VALUES (?, ?, ?, ?, ?)`
  );
  for (const rec of parsed.records) {
    const dec = decodeRecord(rec);
    insertRec.run(
      fileId, rec.index, rec.tsSec, rec.tsSubsec, rec.inclLen, rec.origLen,
      rec.headerOffset, rec.dataOffset,
      dec.status, dec.reason ?? null,
      dec.ethernet?.src ?? null, dec.ethernet?.dst ?? null,
      dec.ipv4?.src ?? null, dec.ipv4?.dst ?? null,
      dec.udp?.srcPort ?? null, dec.udp?.dstPort ?? null, dec.udp?.length ?? null,
      dec.digest ?? null
    );
  }
  for (const d of parsed.diagnostics) {
    insertDiag.run(fileId, d.recordIndex, d.offset, d.code, d.message);
  }
  return {
    fileId, status: status as "ok" | "partial", sha256: hash,
    recordCount: parsed.records.length,
    diagnosticCount: parsed.diagnostics.length,
    truncated: parsed.truncated,
  };
}

export function getFileRow(fileId: number): FileRow {
  const row = getDb().prepare(`SELECT * FROM files WHERE id = ?`).get(fileId) as FileRow | undefined;
  if (!row) throw new ApiError("NOT_FOUND", `抓包文件 id=${fileId} 不存在`, 404);
  return row;
}

/** 读取固定副本并核对摘要：替换文件不会让旧偏移指向新内容 */
export function loadVerifiedBytes(row: FileRow): Buffer {
  const abs = path.resolve(PROJECT_ROOT, row.blob_path);
  if (!fs.existsSync(abs)) {
    throw new ApiError("FILE_CHANGED", `固定副本缺失：${row.blob_path}`, 409);
  }
  const buf = fs.readFileSync(abs);
  if (sha256(buf) !== row.sha256) {
    throw new ApiError("FILE_CHANGED", `固定副本摘要与导入时不一致，拒绝按旧偏移读取`, 409);
  }
  return buf;
}

export function listFiles(): FileRow[] {
  return getDb().prepare(`SELECT * FROM files ORDER BY id`).all() as unknown as FileRow[];
}

export function listPackets(fileId: number): RecordRow[] {
  getFileRow(fileId);
  return getDb().prepare(`SELECT * FROM records WHERE file_id = ? ORDER BY idx`).all(fileId) as unknown as RecordRow[];
}

export function getRecordRow(fileId: number, idx: number): RecordRow {
  getFileRow(fileId);
  const row = getDb().prepare(`SELECT * FROM records WHERE file_id = ? AND idx = ?`).get(fileId, idx) as RecordRow | undefined;
  if (!row) throw new ApiError("NOT_FOUND", `记录 #${idx} 不存在`, 404);
  return row;
}

export interface RecordDetail {
  record: RecordRow;
  timestampNano: string;
  decode: DecodeResult;
}

/** 按记录读取协议层：重启后仍从固定副本取原始字节重新解码并核对 */
export function getRecordDetail(fileId: number, idx: number): RecordDetail {
  const fileRow = getFileRow(fileId);
  const recRow = getRecordRow(fileId, idx);
  const buf = loadVerifiedBytes(fileRow);
  const parsed = parsePcap(buf, config.maxRecords);
  const rec = parsed.records[idx];
  if (!rec || rec.headerOffset !== recRow.header_offset || rec.inclLen !== recRow.incl_len) {
    throw new ApiError("FILE_CHANGED", `记录 #${idx} 偏移与导入时不一致`, 409);
  }
  return {
    record: recRow,
    timestampNano: timestampToNanoString(rec.tsSec, rec.tsSubsec, fileRow.precision as SubsecPrecision),
    decode: decodeRecord(rec),
  };
}

/** 查询原始偏移处的字节（以导入时固定副本为准） */
export function getRawBytes(fileId: number, offset: number, length: number) {
  if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(length) || length < 1 || length > 65536) {
    throw new ApiError("INVALID_ARGUMENT", `非法的 offset/length（offset>=0, 1<=length<=65536）`, 400);
  }
  const row = getFileRow(fileId);
  const buf = loadVerifiedBytes(row);
  if (offset >= buf.length) {
    throw new ApiError("INVALID_ARGUMENT", `offset=${offset} 超出文件大小 ${buf.length}`, 400);
  }
  const end = Math.min(offset + length, buf.length);
  return {
    offset,
    requestedLength: length,
    returnedLength: end - offset,
    fileSize: buf.length,
    hex: buf.subarray(offset, end).toString("hex"),
  };
}

export interface UdpFilter {
  src?: string; dst?: string; sport?: number; dport?: number;
}

export function filterUdp(fileId: number, f: UdpFilter): RecordRow[] {
  getFileRow(fileId);
  const conds: string[] = [`file_id = ?`, `udp_sport IS NOT NULL`];
  const params: (string | number)[] = [fileId];
  if (f.src !== undefined) { conds.push(`ip_src = ?`); params.push(f.src); }
  if (f.dst !== undefined) { conds.push(`ip_dst = ?`); params.push(f.dst); }
  if (f.sport !== undefined) { conds.push(`udp_sport = ?`); params.push(f.sport); }
  if (f.dport !== undefined) { conds.push(`udp_dport = ?`); params.push(f.dport); }
  return getDb().prepare(
    `SELECT * FROM records WHERE ${conds.join(" AND ")} ORDER BY idx`
  ).all(...params) as unknown as RecordRow[];
}

export function getDiagnostics(fileId: number): DiagnosticRow[] {
  getFileRow(fileId);
  return getDb().prepare(`SELECT * FROM diagnostics WHERE file_id = ? ORDER BY id`).all(fileId) as unknown as DiagnosticRow[];
}

/** 重新解析固定副本做容器校验（可与导入时结果对照） */
export function validateFile(fileId: number) {
  const row = getFileRow(fileId);
  const buf = loadVerifiedBytes(row);
  try {
    const parsed = parsePcap(buf, config.maxRecords);
    return {
      fileId,
      valid: !parsed.truncated && parsed.diagnostics.length === 0,
      truncated: parsed.truncated,
      recordCount: parsed.records.length,
      diagnostics: parsed.diagnostics,
    };
  } catch (e) {
    if (e instanceof PcapFormatError) {
      return { fileId, valid: false, truncated: false, recordCount: 0, diagnostics: [], fatal: e.message };
    }
    throw e;
  }
}

export function exportReport(fileId: number) {
  const row = getFileRow(fileId);
  const records = listPackets(fileId);
  const diagnostics = getDiagnostics(fileId);
  const precision = row.precision as SubsecPrecision;
  return {
    file: {
      id: row.id, originalPath: row.original_path, sha256: row.sha256, size: row.size,
      byteOrder: row.byte_order, precision: row.precision, version: row.version,
      snaplen: row.snaplen, status: row.status, importedAt: row.imported_at,
    },
    recordCount: records.length,
    records: records.map((r) => ({
      index: r.idx,
      timestamp: { sec: r.ts_sec, subsec: r.ts_subsec, nano: timestampToNanoString(r.ts_sec, r.ts_subsec, precision) },
      inclLen: r.incl_len, origLen: r.orig_len,
      headerOffset: r.header_offset, dataOffset: r.data_offset,
      decodeStatus: r.decode_status, decodeReason: r.decode_reason,
      ipSrc: r.ip_src, ipDst: r.ip_dst, udpSport: r.udp_sport, udpDport: r.udp_dport,
    })),
    diagnostics: diagnostics.map((d) => ({
      recordIndex: d.record_idx, offset: d.offset, code: d.code, message: d.message,
    })),
  };
}
