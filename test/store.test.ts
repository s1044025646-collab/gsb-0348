import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { Store } from "../src/db.js";
import { pcapFile, udpFrame } from "../src/synth.js";
import { startServer } from "../src/api.js";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-test-"));
  fs.mkdirSync(path.join(dir, "inputs"), { recursive: true });
  return dir;
}

test("import, restart, re-read same record and bytes", () => {
  const proj = tmpProject();
  const dataDir = path.join(proj, "data");
  const src = path.join(proj, "inputs", "a.pcap");
  fs.writeFileSync(src, pcapFile({}, [
    { tsSec: 1700000000, tsFrac: 42, data: udpFrame({ payload: Buffer.from("persist-me") }) },
  ]));
  const store1 = new Store(dataDir);
  const imp = store1.importCapture(src, proj);
  assert.equal(imp.status, "valid");
  assert.equal(imp.packetCount, 1);
  store1.db.close();

  // restart: new Store on same data dir
  const store2 = new Store(dataDir);
  const det = store2.packetDetail(imp.id, 0);
  assert.equal(det.decode.udp!.srcPort, 5000);
  assert.equal(det.tsNs, "1700000000000042000");
  const raw = store2.rawSlice(imp.id, det.dataOffset, 4);
  assert.equal(raw.hex, Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]).toString("hex"));
  const val = store2.validate(imp.id);
  assert.equal(val.consistent, true);
  store2.db.close();
});

test("partial import is not registered as fully valid", () => {
  const proj = tmpProject();
  const dataDir = path.join(proj, "data");
  const good = pcapFile({}, [{ tsSec: 1, tsFrac: 1, data: udpFrame() }]);
  const buf = Buffer.concat([good, Buffer.alloc(8, 0)]); // half record header
  const src = path.join(proj, "inputs", "b.pcap");
  fs.writeFileSync(src, buf);
  const store = new Store(dataDir);
  const imp = store.importCapture(src, proj);
  assert.equal(imp.status, "partial");
  assert.equal(imp.packetCount, 1);
  assert.equal(imp.diagnostics[0].code, "E_TRUNCATED_RECORD_HEADER");
  const cap = store.getCapture(imp.id)!;
  assert.equal(cap.status, "partial");
  store.db.close();
});

test("invalid import keeps no packets", () => {
  const proj = tmpProject();
  const src = path.join(proj, "inputs", "c.pcap");
  fs.writeFileSync(src, Buffer.alloc(24, 0xee));
  const store = new Store(path.join(proj, "data"));
  const imp = store.importCapture(src, proj);
  assert.equal(imp.status, "invalid");
  assert.equal(store.listPackets(imp.id).length, 0);
  store.db.close();
});

test("replacing stored file is detected via hash mismatch", () => {
  const proj = tmpProject();
  const src = path.join(proj, "inputs", "d.pcap");
  fs.writeFileSync(src, pcapFile({}, [{ tsSec: 1, tsFrac: 1, data: udpFrame() }]));
  const store = new Store(path.join(proj, "data"));
  const imp = store.importCapture(src, proj);
  const cap = store.getCapture(imp.id)!;
  fs.writeFileSync(path.join(proj, "data", "files", cap.stored_path), pcapFile({}, []));
  assert.throws(() => store.readStoredBytes(imp.id), /hash mismatch/);
  store.db.close();
});

test("import outside project root refused", () => {
  const proj = tmpProject();
  const outside = path.join(os.tmpdir(), `outside-${Date.now()}.pcap`);
  fs.writeFileSync(outside, pcapFile({}, []));
  const store = new Store(path.join(proj, "data"));
  assert.throws(() => store.importCapture(outside, proj), /outside project/);
  store.db.close();
});

test("UDP filter by ip/port", () => {
  const proj = tmpProject();
  const src = path.join(proj, "inputs", "e.pcap");
  fs.writeFileSync(src, pcapFile({}, [
    { tsSec: 1, tsFrac: 0, data: udpFrame({ srcPort: 53, dstPort: 1 }) },
    { tsSec: 2, tsFrac: 0, data: udpFrame({ srcPort: 5000, dstPort: 6000 }) },
  ]));
  const store = new Store(path.join(proj, "data"));
  const imp = store.importCapture(src, proj);
  const rows = store.filterUdp(imp.id, { srcPort: 53 }) as any[];
  assert.equal(rows.length, 1);
  assert.equal(rows[0].udp_dst_port, 1);
  store.db.close();
});

test("HTTP API end-to-end", async () => {
  const proj = tmpProject();
  const src = path.join(proj, "inputs", "f.pcap");
  fs.writeFileSync(src, pcapFile({}, [
    { tsSec: 9, tsFrac: 8, data: udpFrame({ payload: Buffer.from("api") }) },
  ]));
  const store = new Store(path.join(proj, "data"));
  const { server, port } = await startServer(store, proj, 0);
  assert.ok(port > 0);
  const base = `http://127.0.0.1:${port}`;
  const post = await fetch(`${base}/captures`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ path: "inputs/f.pcap" }),
  });
  assert.equal(post.status, 201);
  const imp = await post.json() as any;
  const pkts = await (await fetch(`${base}/captures/${imp.id}/packets`)).json() as any[];
  assert.equal(pkts.length, 1);
  const detail = await (await fetch(`${base}/captures/${imp.id}/packets/0`)).json() as any;
  assert.equal(detail.decode.udp.srcPort, 5000);
  const val = await (await fetch(`${base}/captures/${imp.id}/validate`)).json() as any;
  assert.equal(val.consistent, true);
  const lim = await (await fetch(`${base}/limits`)).json() as any;
  assert.equal(lim.supported.format.includes("2.4"), true);
  const bad = await fetch(`${base}/captures/999`);
  assert.equal(bad.status, 404);
  await new Promise((r) => server.close(r));
  store.db.close();
});
