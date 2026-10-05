import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { parsePcap } from "../src/pcap/parser.js";
import { decodeRecord } from "../src/pcap/decode.js";

const FX = path.resolve(process.cwd(), "fixtures");
const rec = (n: string, i = 0) => parsePcap(fs.readFileSync(path.join(FX, n)), 1000).records[i];

test("正常 UDP 解码：端口/地址/载荷偏移", () => {
  const d = decodeRecord(rec("le-usec.pcap", 0));
  assert.equal(d.status, "decoded");
  assert.equal(d.ethernet!.src, "11:22:33:44:55:66");
  assert.equal(d.ipv4!.src, "192.168.0.1");
  assert.equal(d.ipv4!.dst, "192.168.0.2");
  assert.equal(d.udp!.srcPort, 5000);
  assert.equal(d.udp!.dstPort, 9000);
  assert.equal(d.udp!.payloadLength, 9);
  // 载荷偏移 = 14(eth) + 20(ip) + 8(udp) = 42
  assert.equal(d.udp!.payloadOffset, 42);
});

test("IPv4 选项：按 IHL 跳过", () => {
  const d = decodeRecord(rec("le-usec.pcap", 1));
  assert.equal(d.status, "decoded");
  assert.equal(d.ipv4!.ihl, 6);
  assert.equal(d.udp!.srcPort, 1234);
  assert.equal(d.udp!.dstPort, 53);
  // 载荷偏移 = 14 + 24 + 8 = 46
  assert.equal(d.udp!.payloadOffset, 46);
});

test("大小端解码结果一致", () => {
  const a = decodeRecord(rec("le-usec.pcap", 0));
  const b = decodeRecord(rec("be-nsec.pcap", 0));
  assert.equal(a.udp!.srcPort, b.udp!.srcPort);
  assert.equal(a.udp!.dstPort, b.udp!.dstPort);
  assert.equal(a.ipv4!.src, b.ipv4!.src);
});

test("snaplen 截短：未完整捕获而非矛盾", () => {
  const d = decodeRecord(rec("snaplen-truncated.pcap"));
  assert.equal(d.status, "incomplete_capture");
  assert.ok(d.udp); // 头部可读
  assert.ok(d.udp!.capturedPayloadLength < d.udp!.payloadLength);
});

test("未支持协议（ARP）：保留摘要标未解码", () => {
  const d = decodeRecord(rec("unsupported-arp.pcap"));
  assert.equal(d.status, "undecoded");
  assert.ok(d.digest && d.digest.length > 0);
  assert.equal(d.udp, undefined);
});

test("分片包：标 fragmented，不伪装成 UDP", () => {
  const d = decodeRecord(rec("fragmented.pcap"));
  assert.equal(d.status, "fragmented");
  assert.equal(d.udp, undefined);
});

test("Ethernet 尾部填充不属于 UDP 载荷", () => {
  const d = decodeRecord(rec("eth-padding.pcap"));
  assert.equal(d.status, "decoded");
  assert.equal(d.udp!.payloadLength, 2); // "ab"，不含 18 字节填充
});

test("UDP 长度超过 IP 声明范围：字段矛盾", () => {
  const d = decodeRecord(rec("udp-len-contradiction.pcap"));
  assert.equal(d.status, "contradiction");
});

test("手工核对载荷字节内容", () => {
  const r = rec("le-usec.pcap", 0);
  const d = decodeRecord(r);
  const payload = r.data.subarray(d.udp!.payloadOffset, d.udp!.payloadOffset + d.udp!.payloadLength);
  assert.equal(payload.toString("utf8"), "hello-udp");
});
