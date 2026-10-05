// 存储/服务层测试：独立数据目录、重启读取、输入不可变性、失败不登记。
import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pcap-test-"));
process.env.PCAP_DATA_DIR = tmp;

const svc = await import("../src/service.js");
const { resetDb } = await import("../src/store.js");
const { ApiError } = await import("../src/errors.js");

const FX = path.resolve(process.cwd(), "fixtures");

before(() => { resetDb(); });

test("导入正常文件并列出包", () => {
  const r = svc.importFile(path.join("fixtures", "le-usec.pcap"));
  assert.equal(r.status, "ok");
  assert.equal(r.recordCount, 2);
  const rows = svc.listPackets(r.fileId);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].udp_sport, 5000);
  assert.equal(rows[1].udp_dport, 53);
});

test("导入坏文件不登记为有效抓包", () => {
  const before = svc.listFiles().length;
  assert.throws(
    () => svc.importFile(path.join("fixtures", "bad-magic.pcap")),
    (e: unknown) => e instanceof ApiError && (e as InstanceType<typeof ApiError>).code === "UNSUPPORTED_FORMAT"
  );
  assert.equal(svc.listFiles().length, before);
});

test("截断文件导入为 partial 并保留诊断", () => {
  const r = svc.importFile(path.join("fixtures", "length-overrun.pcap"));
  assert.equal(r.status, "partial");
  const diags = svc.getDiagnostics(r.fileId);
  assert.ok(diags.some((d) => d.code === "TRUNCATED_PACKET_DATA"));
});

test("重启后（重开数据库）读取同一记录并核对原字节", () => {
  const r = svc.importFile(path.join("fixtures", "be-nsec.pcap"));
  resetDb(); // 模拟重启
  const d = svc.getRecordDetail(r.fileId, 1);
  assert.equal(d.timestampNano, "1700000001999999999");
  assert.equal(d.decode.udp!.dstPort, 53);
});

test("替换原文件后旧偏移仍指向导入时内容（固定副本）", () => {
  const src = path.join(FX, "le-usec.pcap");
  const original = fs.readFileSync(src);
  const r = svc.importFile(path.join("fixtures", "le-usec.pcap"));
  const before1 = svc.getRecordDetail(r.fileId, 0);
  fs.copyFileSync(path.join(FX, "be-nsec.pcap"), src); // 替换源文件
  try {
    const after1 = svc.getRecordDetail(r.fileId, 0);
    assert.equal(after1.timestampNano, before1.timestampNano);
    assert.equal(after1.decode.udp!.srcPort, 5000);
  } finally {
    fs.writeFileSync(src, original); // 恢复夹具
  }
});

test("原始偏移读取越界报错", () => {
  const r = svc.importFile(path.join("fixtures", "empty.pcap"));
  assert.throws(() => svc.getRawBytes(r.fileId, 10_000, 4), /超出文件大小/);
  assert.throws(() => svc.getRawBytes(r.fileId, -1, 4), /非法/);
});

test("UDP 过滤", () => {
  const rows = svc.filterUdp(1, { dport: 53 });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].udp_sport, 1234);
});

test("报告导出包含诊断与时间戳纳秒字符串", () => {
  const r = svc.importFile(path.join("fixtures", "bad-subsec.pcap"));
  const rep = svc.exportReport(r.fileId);
  assert.ok(rep.diagnostics.some((d) => d.code === "SUBSECOND_OUT_OF_RANGE"));
  assert.match(rep.records[0].timestamp.nano, /^\d+$/);
});

test("项目外路径被拒绝", () => {
  assert.throws(
    () => svc.importFile(path.join("..", "outside.pcap")),
    (e: unknown) => e instanceof ApiError && (e as InstanceType<typeof ApiError>).code === "PATH_OUT_OF_SCOPE"
  );
});
