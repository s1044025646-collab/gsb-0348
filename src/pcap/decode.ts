// Ethernet / IPv4 / 未分片 UDP 字段解码。
// 严格区分：抓取截短(incomplete_capture) 与 字段自相矛盾(contradiction)。
import type { PacketRecord } from "./parser.js";

export type DecodeStatus =
  | "decoded"            // 完整 UDP 解码
  | "incomplete_capture" // snaplen 截短导致头部或载荷不足
  | "contradiction"      // 字段自相矛盾（坏包）
  | "fragmented"         // IPv4 分片，保留摘要不解 UDP
  | "undecoded";         // 不支持的封装/协议，保留摘要

export interface LayerInfo {
  name: string;
  offset: number; // 相对包数据起点
  length: number;
  fields: Record<string, string | number>;
}

export interface DecodeResult {
  status: DecodeStatus;
  reason?: string;
  layers: LayerInfo[];
  ethernet?: { src: string; dst: string; ethertype: number };
  ipv4?: {
    src: string; dst: string; protocol: number; ihl: number;
    totalLength: number; identification: number; ttl: number;
    flagsFragment: number;
  };
  udp?: {
    srcPort: number; dstPort: number; length: number;
    payloadLength: number; capturedPayloadLength: number;
    payloadOffset: number; // 相对包数据起点
  };
  /** 未解码时的字节摘要（前 32 字节 hex） */
  digest?: string;
}

const ETH_HEADER_LEN = 14;
const ETHERTYPE_IPV4 = 0x0800;
const IPPROTO_UDP = 17;

function macAt(buf: Buffer, o: number): string {
  return Array.from(buf.subarray(o, o + 6)).map((b) => b.toString(16).padStart(2, "0")).join(":");
}
function ipv4At(buf: Buffer, o: number): string {
  return `${buf[o]}.${buf[o + 1]}.${buf[o + 2]}.${buf[o + 3]}`;
}
function hexDigest(buf: Buffer): string {
  return buf.subarray(0, Math.min(32, buf.length)).toString("hex");
}

export function decodeRecord(rec: PacketRecord): DecodeResult {
  const data = rec.data;
  const layers: LayerInfo[] = [];
  const fail = (status: DecodeStatus, reason: string, extra?: Partial<DecodeResult>): DecodeResult =>
    ({ status, reason, layers, digest: hexDigest(data), ...extra });

  // --- Ethernet ---
  if (data.length < ETH_HEADER_LEN) {
    return fail("incomplete_capture",
      `捕获数据 ${data.length} 字节不足以容纳 Ethernet 头（需要 ${ETH_HEADER_LEN}）`);
  }
  const eth = {
    dst: macAt(data, 0),
    src: macAt(data, 6),
    ethertype: data.readUInt16BE(12),
  };
  layers.push({
    name: "ethernet", offset: 0, length: ETH_HEADER_LEN,
    fields: { src: eth.src, dst: eth.dst, ethertype: `0x${eth.ethertype.toString(16).padStart(4, "0")}` },
  });
  if (eth.ethertype !== ETHERTYPE_IPV4) {
    return fail("undecoded", `不支持的 ethertype 0x${eth.ethertype.toString(16)}，保留字节摘要`, { ethernet: eth });
  }

  // --- IPv4 ---
  const ipOff = ETH_HEADER_LEN;
  if (data.length < ipOff + 20) {
    return fail("incomplete_capture",
      `捕获数据不足以容纳最小 IPv4 头（需要 ${ipOff + 20}，实际 ${data.length}）`, { ethernet: eth });
  }
  const vhl = data[ipOff];
  const version = vhl >> 4;
  const ihl = vhl & 0x0f;
  if (version !== 4) {
    return fail("contradiction", `EtherType 为 IPv4 但版本字段=${version}`, { ethernet: eth });
  }
  if (ihl < 5) {
    return fail("contradiction", `IPv4 IHL=${ihl} 小于最小值 5`, { ethernet: eth });
  }
  const ihlBytes = ihl * 4;
  if (data.length < ipOff + ihlBytes) {
    return fail("incomplete_capture",
      `捕获数据不足以容纳 IPv4 头含选项（IHL=${ihlBytes} 字节）`, { ethernet: eth });
  }
  const totalLength = data.readUInt16BE(ipOff + 2);
  const flagsFragment = data.readUInt16BE(ipOff + 6);
  const protocol = data[ipOff + 9];
  const ipv4 = {
    src: ipv4At(data, ipOff + 12),
    dst: ipv4At(data, ipOff + 16),
    protocol, ihl, totalLength,
    identification: data.readUInt16BE(ipOff + 4),
    ttl: data[ipOff + 8],
    flagsFragment,
  };
  if (totalLength < ihlBytes) {
    return fail("contradiction",
      `IPv4 total_length=${totalLength} 小于头长 IHL=${ihlBytes}`, { ethernet: eth, ipv4 });
  }
  // 网络层范围由 total_length 约束；链路层填充不属于 IP/UDP
  const ipCaptured = data.length - ipOff;
  const ipAvailable = Math.min(totalLength, ipCaptured);
  const ipTruncated = ipCaptured < totalLength;
  layers.push({
    name: "ipv4", offset: ipOff, length: ihlBytes,
    fields: {
      src: ipv4.src, dst: ipv4.dst, protocol, ihl: ihlBytes,
      total_length: totalLength, identification: ipv4.identification, ttl: ipv4.ttl,
      captured: ipCaptured, truncated: ipTruncated ? 1 : 0,
    },
  });

  const mfSet = (flagsFragment & 0x2000) !== 0;
  const fragOffset = flagsFragment & 0x1fff;
  if (mfSet || fragOffset !== 0) {
    return fail("fragmented",
      `IPv4 分片包（MF=${mfSet ? 1 : 0}, offset=${fragOffset}），不做重组`, { ethernet: eth, ipv4 });
  }
  if (protocol !== IPPROTO_UDP) {
    return fail("undecoded", `不支持的 IP 协议号 ${protocol}，保留字节摘要`, { ethernet: eth, ipv4 });
  }

  // --- UDP ---
  const udpOff = ipOff + ihlBytes;
  const ipPayloadDeclared = totalLength - ihlBytes;
  const ipPayloadCaptured = ipAvailable - ihlBytes;
  if (ipPayloadCaptured < 8) {
    return fail(ipTruncated ? "incomplete_capture" : "contradiction",
      ipTruncated
        ? `抓取截短：IP 载荷仅捕获 ${ipPayloadCaptured} 字节，不足 UDP 头`
        : `IP 声明载荷 ${ipPayloadDeclared} 字节，不足 UDP 头`, { ethernet: eth, ipv4 });
  }
  const udpSrc = data.readUInt16BE(udpOff);
  const udpDst = data.readUInt16BE(udpOff + 2);
  const udpLen = data.readUInt16BE(udpOff + 4);
  if (udpLen < 8) {
    return fail("contradiction", `UDP length=${udpLen} 小于自身头长 8`, { ethernet: eth, ipv4 });
  }
  if (udpLen > ipPayloadDeclared) {
    return fail("contradiction",
      `UDP length=${udpLen} 超过 IP 声明的载荷范围 ${ipPayloadDeclared}`, { ethernet: eth, ipv4 });
  }
  const payloadOffset = udpOff + 8;
  const payloadDeclared = udpLen - 8;
  const payloadCaptured = Math.max(0, Math.min(payloadDeclared, ipPayloadCaptured - 8));
  const payloadTruncated = payloadCaptured < payloadDeclared;
  const udp = {
    srcPort: udpSrc, dstPort: udpDst, length: udpLen,
    payloadLength: payloadDeclared,
    capturedPayloadLength: payloadCaptured,
    payloadOffset,
  };
  layers.push({
    name: "udp", offset: udpOff, length: 8,
    fields: {
      src_port: udpSrc, dst_port: udpDst, length: udpLen,
      payload_declared: payloadDeclared, payload_captured: payloadCaptured,
    },
  });
  if (payloadTruncated) {
    return {
      status: "incomplete_capture",
      reason: `抓取截短：UDP 载荷声明 ${payloadDeclared} 字节，仅捕获 ${payloadCaptured} 字节`,
      layers, ethernet: eth, ipv4, udp, digest: hexDigest(data),
    };
  }
  return { status: "decoded", layers, ethernet: eth, ipv4, udp };
}
