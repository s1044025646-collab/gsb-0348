import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { parsePcap, parseGlobalHeader, timestampToNanoString, PcapFormatError } from "../src/pcap/parser.js";

const FX = path.resolve(process.cwd(), "fixtures");
const read = (n: string) => fs.readFileSync(path.join(FX, n));

test("小端微秒全局头", () => {
  const h = parseGlobalHeader(read("le-usec.pcap"));
  assert.equal(h.byteOrder, "le");
  assert.equal(h.precision, "micro");
  assert.equal(h.versionMajor, 2);
  assert.equal(h.versionMinor, 4);
  assert.equal(h.network, 1);
});

test("大端纳秒全局头", () => {
  const h = parseGlobalHeader(read("be-nsec.pcap"));
  assert.equal(h.byteOrder, "be");
  assert.equal(h.precision, "nano");
});

test("大小端表达相同帧得到一致记录字段", () => {
  const a = parsePcap(read("le-usec.pcap"), 1000);
  const b = parsePcap(read("be-nsec.pcap"), 1000);
  assert.equal(a.records.length, 2);
  assert.equal(b.records.length, 2);
  for (let i = 0; i < 2; i++) {
    assert.equal(a.records[i].tsSec, b.records[i].tsSec);
    assert.equal(a.records[i].inclLen, b.records[i].inclLen);
    assert.deepEqual(a.records[i].data, b.records[i].data);
  }
  // 微秒 123456 == 纳秒 123456000（语义一致）
  assert.equal(a.records[0].tsSubsec * 1000, b.records[0].tsSubsec - 789);
});

test("纳秒字符串不丢低位（BigInt 精确）", () => {
  assert.equal(timestampToNanoString(1700000001, 999999999, "nano"), "1700000001999999999");
  assert.equal(timestampToNanoString(1700000000, 123456, "micro"), "1700000000123456000");
  assert.equal(timestampToNanoString(0, 1, "nano"), "1");
});

test("空抓包：零记录零诊断", () => {
  const r = parsePcap(read("empty.pcap"), 1000);
  assert.equal(r.records.length, 0);
  assert.equal(r.diagnostics.length, 0);
  assert.equal(r.truncated, false);
});

test("坏 magic 抛格式错误", () => {
  assert.throws(() => parsePcap(read("bad-magic.pcap"), 1000), PcapFormatError);
});

test("半个记录头：诊断含偏移与记录号，不产生记录", () => {
  const r = parsePcap(read("half-record-header.pcap"), 1000);
  assert.equal(r.records.length, 0);
  assert.equal(r.truncated, true);
  const d = r.diagnostics[0];
  assert.equal(d.code, "TRUNCATED_RECORD_HEADER");
  assert.equal(d.recordIndex, 0);
  assert.equal(d.offset, 24);
});

test("长度越界：容器截断，不越界读取也不吞下一包", () => {
  const r = parsePcap(read("length-overrun.pcap"), 1000);
  assert.equal(r.records.length, 0);
  assert.equal(r.truncated, true);
  const d = r.diagnostics.find((x) => x.code === "TRUNCATED_PACKET_DATA");
  assert.ok(d);
  assert.equal(d!.recordIndex, 0);
  assert.equal(d!.offset, 24 + 16);
});

test("非法子秒字段被诊断", () => {
  const r = parsePcap(read("bad-subsec.pcap"), 1000);
  const d = r.diagnostics.find((x) => x.code === "SUBSECOND_OUT_OF_RANGE");
  assert.ok(d);
  assert.equal(d!.offset, 24 + 4);
});

test("snaplen 截短是正常抓取截短，不是坏文件", () => {
  const r = parsePcap(read("snaplen-truncated.pcap"), 1000);
  assert.equal(r.truncated, false);
  assert.equal(r.records.length, 1);
  assert.equal(r.records[0].inclLen, 60);
  assert.ok(r.records[0].origLen > 60);
});

test("时间戳倒退时记录顺序保持文件原样", () => {
  const r = parsePcap(read("out-of-order-ts.pcap"), 1000);
  assert.equal(r.records[0].tsSec, 1700000800);
  assert.equal(r.records[1].tsSec, 1700000700);
});

test("记录数上限", () => {
  assert.throws(() => parsePcap(read("le-usec.pcap"), 1), /上限/);
});
