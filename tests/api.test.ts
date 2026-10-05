// API 集成测试：随机空闲端口、导入、列包、详情、raw、过滤、报告、错误码。
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { Server } from "node:http";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-api-test-"));
process.env.PCAP_DATA_DIR = tmp;

const { startServer } = await import("../src/api.js");

let server: Server;
let base: string;

before(async () => {
  const started = await startServer(0); // 自动空闲端口
  server = started.server;
  base = `http://127.0.0.1:${started.port}`;
  assert.ok(started.port > 0);
});

after(() => { server.close(); });

async function api(method: string, p: string, body?: unknown) {
  const res = await fetch(base + p, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

test("limits 暴露支持范围与上限", async () => {
  const r = await api("GET", "/api/limits");
  assert.equal(r.status, 200);
  assert.ok(r.json.maxFileSize > 0);
  assert.deepEqual(r.json.supportedVersions, ["2.4"]);
});

test("导入 -> 列包 -> 详情 -> raw -> 过滤 -> 报告", async () => {
  const imp = await api("POST", "/api/import", { path: "fixtures/le-usec.pcap" });
  assert.equal(imp.status, 201);
  const id = imp.json.fileId;

  const pkts = await api("GET", `/api/files/${id}/packets`);
  assert.equal(pkts.json.length, 2);

  const detail = await api("GET", `/api/files/${id}/packets/0`);
  assert.equal(detail.json.decode.udp.srcPort, 5000);
  assert.equal(detail.json.timestampNano, "1700000000123456000");

  const raw = await api("GET", `/api/files/${id}/raw?offset=0&length=4`);
  assert.equal(raw.json.hex, "d4c3b2a1"); // 小端微秒 magic

  const filt = await api("GET", `/api/files/${id}/udp?dport=53`);
  assert.equal(filt.json.length, 1);

  const rep = await api("GET", `/api/files/${id}/report`);
  assert.equal(rep.json.recordCount, 2);

  const val = await api("POST", `/api/files/${id}/validate`);
  assert.equal(val.json.valid, true);
});

test("坏文件导入返回 UNSUPPORTED_FORMAT", async () => {
  const r = await api("POST", "/api/import", { path: "fixtures/bad-magic.pcap" });
  assert.equal(r.status, 422);
  assert.equal(r.json.error.code, "UNSUPPORTED_FORMAT");
});

test("项目外路径返回 PATH_OUT_OF_SCOPE", async () => {
  const r = await api("POST", "/api/import", { path: "../x.pcap" });
  assert.equal(r.status, 403);
  assert.equal(r.json.error.code, "PATH_OUT_OF_SCOPE");
});

test("缺失参数与未知路由", async () => {
  const r1 = await api("POST", "/api/import", {});
  assert.equal(r1.json.error.code, "INVALID_ARGUMENT");
  const r2 = await api("GET", "/api/nope");
  assert.equal(r2.status, 404);
});

test("不存在的文件与记录", async () => {
  const r1 = await api("POST", "/api/import", { path: "fixtures/nope.pcap" });
  assert.equal(r1.json.error.code, "NOT_FOUND");
  const r2 = await api("GET", "/api/files/999/packets");
  assert.equal(r2.json.error.code, "NOT_FOUND");
});
