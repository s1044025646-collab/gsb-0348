// SQLite 存储层（node:sqlite，无原生依赖）。
// 保存：文件摘要、项目内固定副本位置、格式版本、记录索引、诊断。
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import { dbPath } from "./config.js";

export interface FileRow {
  id: number;
  original_path: string;
  blob_path: string;
  sha256: string;
  size: number;
  byte_order: string;
  precision: string;
  version: string;
  snaplen: number;
  status: string; // ok | partial | failed
  record_count: number;
  diagnostic_count: number;
  imported_at: string;
}

export interface RecordRow {
  id: number;
  file_id: number;
  idx: number;
  ts_sec: number;
  ts_subsec: number;
  incl_len: number;
  orig_len: number;
  header_offset: number;
  data_offset: number;
  decode_status: string;
  decode_reason: string | null;
  eth_src: string | null;
  eth_dst: string | null;
  ip_src: string | null;
  ip_dst: string | null;
  udp_sport: number | null;
  udp_dport: number | null;
  udp_len: number | null;
  digest: string | null;
}

export interface DiagnosticRow {
  id: number;
  file_id: number;
  record_idx: number | null;
  offset: number;
  code: string;
  message: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  original_path TEXT NOT NULL,
  blob_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  byte_order TEXT NOT NULL,
  precision TEXT NOT NULL,
  version TEXT NOT NULL,
  snaplen INTEGER NOT NULL,
  status TEXT NOT NULL,
  record_count INTEGER NOT NULL,
  diagnostic_count INTEGER NOT NULL,
  imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  idx INTEGER NOT NULL,
  ts_sec INTEGER NOT NULL,
  ts_subsec INTEGER NOT NULL,
  incl_len INTEGER NOT NULL,
  orig_len INTEGER NOT NULL,
  header_offset INTEGER NOT NULL,
  data_offset INTEGER NOT NULL,
  decode_status TEXT NOT NULL,
  decode_reason TEXT,
  eth_src TEXT, eth_dst TEXT,
  ip_src TEXT, ip_dst TEXT,
  udp_sport INTEGER, udp_dport INTEGER, udp_len INTEGER,
  digest TEXT,
  UNIQUE(file_id, idx)
);
CREATE TABLE IF NOT EXISTS diagnostics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  record_idx INTEGER,
  offset INTEGER NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_file ON records(file_id, idx);
CREATE INDEX IF NOT EXISTS idx_records_udp ON records(file_id, udp_sport, udp_dport);
`;

let db: DatabaseSync | null = null;

export function getDb(): DatabaseSync {
  if (!db) {
    fs.mkdirSync(path_dirname(dbPath()), { recursive: true });
    db = new DatabaseSync(dbPath());
    db.exec(SCHEMA);
  }
  return db;
}

import path from "node:path";
function path_dirname(p: string): string {
  return path.dirname(p);
}

/** 测试用：关闭并重置连接（配合删除数据目录） */
export function resetDb(): void {
  if (db) { db.close(); db = null; }
}
