import test from "node:test";
import assert from "node:assert/strict";
import { parsePcap, tsToNsString, DEFAULT_LIMITS } from "../src/pcap.js";
import { pcapFile, udpFrame, globalHeader, recordHeader } from "../src/synth.js";

test("empty capture is valid with zero records", () => {
  const r = parsePcap(pcapFile({}, []));
  assert.equal(r.ok, true);
  assert.equal(r.records.length, 0);
});

test("bad magic rejected with offset 0", () => {
  const r = parsePcap(Buffer.alloc(24, 0xff));
  assert.equal(r.ok, false);
  assert.equal(r.diagnostics[0].code, "E_BAD_MAGIC");
  assert.equal(r.diagnostics[0].offset, 0);
});

test("truncated global header", () => {
  const r = parsePcap(Buffer.alloc(10));
  assert.equal(r.diagnostics[0].code, "E_TRUNCATED_GLOBAL_HEADER");
});

test("LE micro and BE nano express identical fields", () => {
  const frame = udpFrame({ payload: Buffer.from("hello-udp") });
  const le = parsePcap(pcapFile({ endianness: "le", precision: "micro" }, [
    { tsSec: 1700000000, tsFrac: 123456, data: frame },
  ]));
  const be = parsePcap(pcapFile({ endianness: "be", precision: "nano" }, [
    { tsSec: 1700000000, tsFrac: 123456000, data: frame },
  ]));
  assert.equal(le.ok && be.ok, true);
  const a = le.records[0], b = be.records[0];
  assert.equal(a.tsNs, b.tsNs);
  assert.equal(a.tsNs, "1700000000123456000");
  assert.deepEqual(a.decode.udp, b.decode.udp);
  assert.deepEqual(a.decode.ipv4, b.decode.ipv4);
  assert.equal(a.decode.udp!.srcPort, 5000);
  assert.equal(a.decode.udp!.dstPort, 6000);
  assert.equal(a.decode.udp!.payloadLength, 9);
  assert.equal(a.decode.status, "decoded");
});

test("exact ns string without float loss", () => {
  assert.equal(tsToNsString(1, 999999999, "nano"), "1999999999");
  assert.equal(tsToNsString(1, 999999, "micro"), "1999999000");
  assert.equal(tsToNsString(0, 1, "nano"), "1");
});

test("IPv4 options skipped via IHL", () => {
  const r = parsePcap(pcapFile({}, [
    { tsSec: 1, tsFrac: 1, data: udpFrame({ ipOptions: Buffer.from([1, 1, 1, 0]) }) },
  ]));
  const d = r.records[0].decode;
  assert.equal(d.status, "decoded");
  assert.equal(d.ipv4!.ihl, 24);
  assert.equal(d.ipv4!.optionsHex, "01010100");
  assert.equal(d.udp!.srcPort, 5000);
});

test("snaplen truncation: incl<orig is truncated_capture, not corrupt", () => {
  const full = udpFrame({ payload: Buffer.alloc(200, 0x41) });
  const r = parsePcap(pcapFile({ snaplen: 96 }, [
    { tsSec: 1, tsFrac: 1, data: full.subarray(0, 60), origLen: full.length },
  ]));
  assert.equal(r.ok, true);
  const rec = r.records[0];
  assert.equal(rec.inclLen, 60);
  assert.equal(rec.origLen, full.length);
  assert.equal(rec.decode.status, "truncated_capture");
  assert.ok(rec.decode.udp); // UDP header still readable
  assert.ok(rec.decode.udp!.payloadCaptured < rec.decode.udp!.payloadLength);
});

test("truncated before UDP header", () => {
  const full = udpFrame();
  const r = parsePcap(pcapFile({}, [
    { tsSec: 1, tsFrac: 1, data: full.subarray(0, 14 + 20 + 4), origLen: full.length },
  ]));
  assert.equal(r.records[0].decode.status, "truncated_capture");
  assert.equal(r.records[0].decode.udp, undefined);
});

test("unsupported ethertype / protocol / fragmentation are undecoded", () => {
  const r = parsePcap(pcapFile({}, [
    { tsSec: 1, tsFrac: 0, data: udpFrame({ etherType: 0x86dd }) },
    { tsSec: 2, tsFrac: 0, data: udpFrame({ protocol: 6 }) },
    { tsSec: 3, tsFrac: 0, data: udpFrame({ fragField: 0x2000 }) },
    { tsSec: 4, tsFrac: 0, data: udpFrame({ fragField: 0x0001 }) },
  ]));
  assert.equal(r.ok, true);
  for (const rec of r.records) assert.equal(rec.decode.status, "undecoded");
  assert.match(r.records[0].decode.reason!, /ethertype/);
  assert.match(r.records[1].decode.reason!, /protocol 6/);
  assert.match(r.records[2].decode.reason!, /fragmented/);
  assert.match(r.records[3].decode.reason!, /fragmented/);
});

test("ethernet padding excluded from UDP payload", () => {
  const r = parsePcap(pcapFile({}, [
    { tsSec: 1, tsFrac: 0, data: udpFrame({ payload: Buffer.from("x"), padding: 18 }) },
  ]));
  const d = r.records[0].decode;
  assert.equal(d.status, "decoded");
  assert.equal(d.ethernet!.paddingLength, 18);
  assert.equal(d.udp!.payloadLength, 1);
});

test("UDP length smaller than header is inconsistent", () => {
  const r = parsePcap(pcapFile({}, [
    { tsSec: 1, tsFrac: 0, data: udpFrame({ udpLength: 4, ipTotalLength: 20 + 4 }) },
  ]));
  assert.equal(r.records[0].decode.status, "inconsistent");
});

test("UDP length exceeding IPv4 payload is inconsistent", () => {
  const r = parsePcap(pcapFile({}, [
    { tsSec: 1, tsFrac: 0, data: udpFrame({ udpLength: 8 + 9 + 10, ipTotalLength: 20 + 8 + 9 }) },
  ]));
  assert.equal(r.records[0].decode.status, "inconsistent");
  assert.match(r.records[0].decode.reason!, /exceeds IPv4 payload/);
});

test("half record header reports offset and record index", () => {
  const buf = Buffer.concat([pcapFile({}, [
    { tsSec: 1, tsFrac: 1, data: udpFrame() },
  ]), Buffer.alloc(8, 0)]);
  const r = parsePcap(buf);
  assert.equal(r.ok, false);
  assert.equal(r.partial, true);
  assert.equal(r.records.length, 1);
  const d = r.diagnostics[0];
  assert.equal(d.code, "E_TRUNCATED_RECORD_HEADER");
  assert.equal(d.recordIndex, 1);
  assert.equal(d.offset, buf.length - 8);
});

test("record declaring bytes beyond EOF is container truncation", () => {
  const hdr = recordHeader({}, 1, 2, 100, 100);
  const buf = Buffer.concat([pcapFile({}, []), hdr, Buffer.alloc(10)]);
  const r = parsePcap(buf);
  assert.equal(r.diagnostics[0].code, "E_TRUNCATED_RECORD_DATA");
  assert.equal(r.diagnostics[0].recordIndex, 0);
});

test("trailing zero bytes are NOT ignored as padding", () => {
  // 16 zero bytes form a syntactically legal empty record (incl=orig=0) and must be
  // parsed as a record, never silently skipped as "padding":
  const buf = Buffer.concat([pcapFile({}, [
    { tsSec: 1, tsFrac: 1, data: udpFrame() },
  ]), Buffer.alloc(16, 0)]);
  const r = parsePcap(buf);
  assert.equal(r.ok, true);
  assert.equal(r.records.length, 2);
  assert.equal(r.records[1].inclLen, 0);
  // 4 trailing zero bytes are a truncated record header -> hard error:
  const buf2 = Buffer.concat([pcapFile({}, [
    { tsSec: 1, tsFrac: 1, data: udpFrame() },
  ]), Buffer.alloc(4, 0)]);
  const r2 = parsePcap(buf2);
  assert.equal(r2.ok, false);
  assert.equal(r2.diagnostics[0].code, "E_TRUNCATED_RECORD_HEADER");
});

test("illegal subsecond field", () => {
  const hdr = recordHeader({}, 1, 1_000_000, 0, 0);
  const r = parsePcap(Buffer.concat([globalHeader({}), hdr]));
  assert.equal(r.diagnostics[0].code, "E_BAD_SUBSECOND");
  assert.equal(r.diagnostics[0].offset, 24 + 4);
});

test("nano precision subsecond limit", () => {
  const hdr = recordHeader({ precision: "nano" }, 1, 1_000_000_000, 0, 0);
  const r = parsePcap(Buffer.concat([globalHeader({ precision: "nano" }), hdr]));
  assert.equal(r.diagnostics[0].code, "E_BAD_SUBSECOND");
});

test("incl_len > snaplen rejected", () => {
  const f = udpFrame();
  const buf = Buffer.concat([globalHeader({ snaplen: 10 }), recordHeader({}, 1, 0, f.length, f.length), f]);
  const r = parsePcap(buf);
  assert.equal(r.diagnostics[0].code, "E_INCL_GT_SNAPLEN");
});

test("incl_len > orig_len rejected", () => {
  const buf = Buffer.concat([globalHeader({}), recordHeader({}, 1, 0, 20, 10), Buffer.alloc(20)]);
  const r = parsePcap(buf);
  assert.equal(r.diagnostics[0].code, "E_INCL_GT_ORIG");
});

test("bad version and linktype rejected", () => {
  const h1 = globalHeader({}); h1.writeUInt16LE(3, 4);
  assert.equal(parsePcap(h1).diagnostics[0].code, "E_BAD_VERSION");
  const h2 = globalHeader({}); h2.writeUInt32LE(101, 20);
  assert.equal(parsePcap(h2).diagnostics[0].code, "E_UNSUPPORTED_LINKTYPE");
});

test("record order preserved even with regressive timestamps", () => {
  const r = parsePcap(pcapFile({}, [
    { tsSec: 100, tsFrac: 0, data: udpFrame({ srcPort: 1 }) },
    { tsSec: 50, tsFrac: 0, data: udpFrame({ srcPort: 2 }) },
  ]));
  assert.equal(r.records[0].tsSec, 100);
  assert.equal(r.records[1].tsSec, 50);
});

test("packet count limit", () => {
  const recs = Array.from({ length: 5 }, (_, i) => ({ tsSec: i, tsFrac: 0, data: udpFrame() }));
  const r = parsePcap(pcapFile({}, recs), { ...DEFAULT_LIMITS, maxPackets: 3 });
  assert.equal(r.ok, false);
  assert.equal(r.partial, true);
  assert.equal(r.records.length, 3);
  assert.equal(r.diagnostics[0].code, "E_LIMIT_PACKETS");
});

test("parser does not mutate input buffer", () => {
  const buf = pcapFile({}, [{ tsSec: 1, tsFrac: 1, data: udpFrame() }]);
  const copy = Buffer.from(buf);
  parsePcap(buf);
  assert.deepEqual(buf, copy);
});
