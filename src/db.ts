import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { parsePcap, PacketRecord, PcapParseResult, Limits, DEFAULT_LIMITS } from "./pcap.js";

export interface CaptureRow {
  id: number;
  name: string;
  sha256: string;
  size: number;
  stored_path: string;
  status: "valid" | "partial" | "invalid";
  endianness: string | null;
  precision: string | null;
  version: string | null;
  snaplen: number | null;
  linktype: number | null;
  packet_count: number;
  imported_at: string;
}

export class Store {
  readonly db: DatabaseSync;
  readonly dataDir: string;
  readonly filesDir: string;
  readonly limits: Limits;

  constructor(dataDir: string, limits: Limits = DEFAULT_LIMITS) {
    this.dataDir = path.resolve(dataDir);
    this.filesDir = path.join(this.dataDir, "files");
    fs.mkdirSync(this.filesDir, { recursive: true });
    this.limits = limits;
    this.db = new DatabaseSync(path.join(this.dataDir, "pcap.db"));
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS captures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size INTEGER NOT NULL,
        stored_path TEXT NOT NULL,
        status TEXT NOT NULL,
        endianness TEXT, precision TEXT, version TEXT,
        snaplen INTEGER, linktype INTEGER,
        packet_count INTEGER NOT NULL DEFAULT 0,
        imported_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS packets (
        capture_id INTEGER NOT NULL,
        idx INTEGER NOT NULL,
        offset INTEGER NOT NULL,
        data_offset INTEGER NOT NULL,
        ts_sec INTEGER NOT NULL,
        ts_frac INTEGER NOT NULL,
        ts_ns TEXT NOT NULL,
        incl_len INTEGER NOT NULL,
        orig_len INTEGER NOT NULL,
        status TEXT NOT NULL,
        reason TEXT,
        eth_src TEXT, eth_dst TEXT, ether_type INTEGER,
        ip_src TEXT, ip_dst TEXT, ip_protocol INTEGER,
        udp_src_port INTEGER, udp_dst_port INTEGER, udp_length INTEGER,
        summary TEXT,
        PRIMARY KEY (capture_id, idx)
      );
      CREATE TABLE IF NOT EXISTS diagnostics (
        capture_id INTEGER NOT NULL,
        record_index INTEGER,
        offset INTEGER NOT NULL,
        code TEXT NOT NULL,
        message TEXT NOT NULL
      );
    `);
  }

  /** Import a pcap file already inside the project. Copies bytes into data/files/<sha256>.pcap. */
  importCapture(sourcePath: string, projectRoot: string) {
    const abs = path.resolve(sourcePath);
    const root = path.resolve(projectRoot);
    if (!abs.startsWith(root + path.sep) && abs !== root) {
      const err = new Error(`path outside project root: ${abs}`);
      (err as any).code = "E_PATH_OUTSIDE";
      throw err;
    }
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
      const err = new Error(`file not found: ${abs}`);
      (err as any).code = "E_NOT_FOUND";
      throw err;
    }
    const buf = fs.readFileSync(abs);
    const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
    const parsed = parsePcap(buf, this.limits);
    const status = parsed.ok ? "valid" : parsed.partial ? "partial" : "invalid";
    const storedName = `${sha256}.pcap`;
    const storedPath = path.join(this.filesDir, storedName);
    if (!fs.existsSync(storedPath)) fs.writeFileSync(storedPath, buf);

    const version =
      parsed.versionMajor !== undefined ? `${parsed.versionMajor}.${parsed.versionMinor}` : null;
    const info = this.db
      .prepare(
        `INSERT INTO captures (name, sha256, size, stored_path, status, endianness, precision, version, snaplen, linktype, packet_count, imported_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        path.basename(abs),
        sha256,
        buf.length,
        storedName,
        status,
        parsed.endianness ?? null,
        parsed.precision ?? null,
        version,
        parsed.snaplen ?? null,
        parsed.linktype ?? null,
        parsed.records.length,
        new Date().toISOString()
      );
    const id = Number(info.lastInsertRowid);
    this.persistParsed(id, parsed);
    return { id, sha256, status, packetCount: parsed.records.length, diagnostics: parsed.diagnostics };
  }

  private persistParsed(id: number, parsed: PcapParseResult) {
    const insPkt = this.db.prepare(
      `INSERT INTO packets (capture_id, idx, offset, data_offset, ts_sec, ts_frac, ts_ns, incl_len, orig_len,
        status, reason, eth_src, eth_dst, ether_type, ip_src, ip_dst, ip_protocol,
        udp_src_port, udp_dst_port, udp_length, summary)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    const insDiag = this.db.prepare(
      `INSERT INTO diagnostics (capture_id, record_index, offset, code, message) VALUES (?, ?, ?, ?, ?)`
    );
    for (const r of parsed.records) {
      insPkt.run(
        id, r.index, r.offset, r.dataOffset, r.tsSec, r.tsFrac, r.tsNs, r.inclLen, r.origLen,
        r.decode.status, r.decode.reason ?? null,
        r.decode.ethernet?.src ?? null, r.decode.ethernet?.dst ?? null,
        r.decode.ethernet?.etherType ?? null,
        r.decode.ipv4?.src ?? null, r.decode.ipv4?.dst ?? null, r.decode.ipv4?.protocol ?? null,
        r.decode.udp?.srcPort ?? null, r.decode.udp?.dstPort ?? null, r.decode.udp?.length ?? null,
        r.decode.byteSummary
      );
    }
    for (const d of parsed.diagnostics) insDiag.run(id, d.recordIndex, d.offset, d.code, d.message);
  }

  getCapture(id: number): CaptureRow | undefined {
    return this.db.prepare(`SELECT * FROM captures WHERE id = ?`).get(id) as CaptureRow | undefined;
  }

  listCaptures(): CaptureRow[] {
    return this.db.prepare(`SELECT * FROM captures ORDER BY id`).all() as unknown as CaptureRow[];
  }

  listPackets(id: number) {
    return this.db.prepare(`SELECT * FROM packets WHERE capture_id = ? ORDER BY idx`).all(id);
  }

  getPacket(id: number, idx: number) {
    return this.db.prepare(`SELECT * FROM packets WHERE capture_id = ? AND idx = ?`).get(id, idx);
  }

  filterUdp(id: number, f: { srcIp?: string; dstIp?: string; srcPort?: number; dstPort?: number }) {
    const cond = ["capture_id = ?", "udp_src_port IS NOT NULL"];
    const args: (string | number)[] = [id];
    if (f.srcIp) { cond.push("ip_src = ?"); args.push(f.srcIp); }
    if (f.dstIp) { cond.push("ip_dst = ?"); args.push(f.dstIp); }
    if (f.srcPort !== undefined) { cond.push("udp_src_port = ?"); args.push(f.srcPort); }
    if (f.dstPort !== undefined) { cond.push("udp_dst_port = ?"); args.push(f.dstPort); }
    return this.db.prepare(`SELECT * FROM packets WHERE ${cond.join(" AND ")} ORDER BY idx`).all(...args);
  }

  diagnostics(id: number) {
    return this.db.prepare(`SELECT * FROM diagnostics WHERE capture_id = ? ORDER BY offset`).all(id);
  }

  /** Read stored bytes; verify sha256 so replaced files cannot alias old offsets. */
  readStoredBytes(id: number): Buffer {
    const cap = this.getCapture(id);
    if (!cap) {
      const err = new Error(`capture ${id} not found`);
      (err as any).code = "E_NOT_FOUND";
      throw err;
    }
    const p = path.join(this.filesDir, cap.stored_path);
    if (!fs.existsSync(p)) {
      const err = new Error(`stored file missing: ${cap.stored_path}`);
      (err as any).code = "E_STORED_MISSING";
      throw err;
    }
    const buf = fs.readFileSync(p);
    const hash = crypto.createHash("sha256").update(buf).digest("hex");
    if (hash !== cap.sha256) {
      const err = new Error(`stored file hash mismatch (expected ${cap.sha256}, got ${hash})`);
      (err as any).code = "E_HASH_MISMATCH";
      throw err;
    }
    return buf;
  }

  /** Re-parse stored bytes and compare with the recorded index. */
  validate(id: number) {
    const cap = this.getCapture(id);
    if (!cap) {
      const err = new Error(`capture ${id} not found`);
      (err as any).code = "E_NOT_FOUND";
      throw err;
    }
    const buf = this.readStoredBytes(id);
    const parsed = parsePcap(buf, this.limits);
    const storedPkts = this.listPackets(id) as any[];
    const consistent =
      parsed.records.length === storedPkts.length &&
      parsed.records.every((r, i) => {
        const s = storedPkts[i];
        return s && s.offset === r.offset && s.incl_len === r.inclLen && s.orig_len === r.origLen && s.ts_ns === r.tsNs;
      });
    return {
      id: cap.id,
      status: cap.status,
      reparsedOk: parsed.ok,
      reparsedRecords: parsed.records.length,
      storedRecords: storedPkts.length,
      consistent,
      diagnostics: parsed.diagnostics,
    };
  }

  /** Full decoded layer detail for one record, recomputed from stored bytes. */
  packetDetail(id: number, idx: number) {
    const row = this.getPacket(id, idx) as any;
    if (!row) {
      const err = new Error(`packet ${idx} not found in capture ${id}`);
      (err as any).code = "E_NOT_FOUND";
      throw err;
    }
    const buf = this.readStoredBytes(id);
    const parsed = parsePcap(buf, this.limits);
    const rec = parsed.records[idx];
    if (!rec) {
      const err = new Error(`record ${idx} not parseable (capture may be truncated earlier)`);
      (err as any).code = "E_NOT_FOUND";
      throw err;
    }
    return rec;
  }

  rawSlice(id: number, offset: number, length: number) {
    if (!Number.isInteger(offset) || !Number.isInteger(length) || offset < 0 || length < 0 || length > 65536) {
      const err = new Error("invalid offset/length (length must be 0..65536)");
      (err as any).code = "E_INVALID_PARAM";
      throw err;
    }
    const buf = this.readStoredBytes(id);
    if (offset + length > buf.length) {
      const err = new Error(`range [${offset}, ${offset + length}) exceeds file size ${buf.length}`);
      (err as any).code = "E_OUT_OF_RANGE";
      throw err;
    }
    return { offset, length, hex: buf.subarray(offset, offset + length).toString("hex") };
  }

  report(id: number) {
    const cap = this.getCapture(id);
    if (!cap) {
      const err = new Error(`capture ${id} not found`);
      (err as any).code = "E_NOT_FOUND";
      throw err;
    }
    return {
      capture: cap,
      packets: this.listPackets(id),
      diagnostics: this.diagnostics(id),
      limits: this.limits,
      supported: {
        format: "classic pcap 2.4",
        linktypes: ["Ethernet(1)"],
        protocols: ["IPv4 (unfragmented)", "UDP"],
        precisions: ["microsecond", "nanosecond"],
        endianness: ["little", "big"],
      },
    };
  }
}

export function packetToRecord(buf: Buffer, r: PacketRecord) {
  return r;
}
