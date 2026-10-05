// 生成合成 PCAP 夹具：大小端、两种时间精度、IPv4 选项、正常 UDP、
// snaplen 截短、未支持协议、空抓包、坏 magic、半记录头、长度越界、
// 非法子秒、分片、Ethernet 尾部填充。
import fs from "node:fs";
import path from "node:path";

const OUT = path.resolve(process.cwd(), "fixtures");

class Writer {
  buf: number[] = [];
  constructor(private le: boolean) {}
  u16(v: number) { this.buf.push(v & 0xff, (v >> 8) & 0xff); if (!this.le) this.swapLast(2); }
  u32(v: number) { this.buf.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff); if (!this.le) this.swapLast(4); }
  private swapLast(n: number) {
    const s = this.buf.splice(this.buf.length - n, n).reverse();
    this.buf.push(...s);
  }
  bytes(b: Buffer | number[]) { this.buf.push(...b); }
  toBuffer() { return Buffer.from(this.buf); }
}

function globalHeader(le: boolean, nano: boolean, snaplen = 65535): Buffer {
  const w = new Writer(le);
  w.u32(nano ? 0xa1b23c4d : 0xa1b2c3d4);
  w.u16(2); w.u16(4);
  w.u32(0); w.u32(0);
  w.u32(snaplen);
  w.u32(1); // Ethernet
  return w.toBuffer();
}

function recordHeader(le: boolean, sec: number, sub: number, incl: number, orig: number): Buffer {
  const w = new Writer(le);
  w.u32(sec); w.u32(sub); w.u32(incl); w.u32(orig);
  return w.toBuffer();
}

function macBytes(s: string): number[] { return s.split(":").map((h) => parseInt(h, 16)); }
function ipBytes(s: string): number[] { return s.split(".").map(Number); }

interface UdpOpts {
  srcMac?: string; dstMac?: string;
  srcIp?: string; dstIp?: string;
  sport?: number; dport?: number;
  payload?: Buffer;
  ipOptions?: Buffer;       // IPv4 选项（使 IHL > 5）
  extraPadding?: number;    // Ethernet 尾部填充（不属于 IP total_length）
  ethertype?: number;
  ipProtocol?: number;
  flagsFragment?: number;
  udpLenOverride?: number;
  ipTotalOverride?: number;
  ttl?: number;
  id?: number;
}

/** 手工构造 Ethernet/IPv4/UDP 帧 */
export function buildFrame(o: UdpOpts = {}): Buffer {
  const payload = o.payload ?? Buffer.from("hello-udp");
  const ipOptions = o.ipOptions ?? Buffer.alloc(0);
  const ihlBytes = 20 + ipOptions.length;
  const udpLen = o.udpLenOverride ?? 8 + payload.length;
  const ipTotal = o.ipTotalOverride ?? ihlBytes + udpLen;
  const ethertype = o.ethertype ?? 0x0800;
  const parts: number[] = [];
  parts.push(...macBytes(o.dstMac ?? "aa:bb:cc:dd:ee:ff"));
  parts.push(...macBytes(o.srcMac ?? "11:22:33:44:55:66"));
  parts.push((ethertype >> 8) & 0xff, ethertype & 0xff);
  if (ethertype === 0x0800) {
    const ihl = ihlBytes / 4;
    parts.push((4 << 4) | ihl, 0); // version+ihl, tos
    parts.push((ipTotal >> 8) & 0xff, ipTotal & 0xff);
    const id = o.id ?? 0x1234;
    parts.push((id >> 8) & 0xff, id & 0xff);
    const ff = o.flagsFragment ?? 0;
    parts.push((ff >> 8) & 0xff, ff & 0xff);
    parts.push(o.ttl ?? 64, o.ipProtocol ?? 17);
    parts.push(0, 0); // checksum 不校验
    parts.push(...ipBytes(o.srcIp ?? "192.168.0.1"));
    parts.push(...ipBytes(o.dstIp ?? "192.168.0.2"));
    parts.push(...ipOptions);
    if ((o.ipProtocol ?? 17) === 17) {
      const sport = o.sport ?? 5000, dport = o.dport ?? 9000;
      parts.push((sport >> 8) & 0xff, sport & 0xff, (dport >> 8) & 0xff, dport & 0xff);
      parts.push((udpLen >> 8) & 0xff, udpLen & 0xff, 0, 0);
      parts.push(...payload);
    } else {
      parts.push(...payload);
    }
  }
  if (o.extraPadding) parts.push(...new Array(o.extraPadding).fill(0));
  return Buffer.from(parts);
}

function pcap(le: boolean, nano: boolean, records: { sec: number; sub: number; data: Buffer; origLen?: number }[], snaplen = 65535): Buffer {
  const chunks: Buffer[] = [globalHeader(le, nano, snaplen)];
  for (const r of records) {
    chunks.push(recordHeader(le, r.sec, r.sub, r.data.length, r.origLen ?? r.data.length));
    chunks.push(r.data);
  }
  return Buffer.concat(chunks);
}

function write(name: string, buf: Buffer): void {
  fs.writeFileSync(path.join(OUT, name), buf);
  console.log(`fixtures/${name}  (${buf.length} bytes)`);
}

function main(): void {
  fs.mkdirSync(OUT, { recursive: true });
  const frame1 = buildFrame({ sport: 5000, dport: 9000, payload: Buffer.from("hello-udp") });
  const frame2 = buildFrame({
    srcIp: "10.0.0.1", dstIp: "10.0.0.2", sport: 1234, dport: 53,
    payload: Buffer.from("dns-like"), ipOptions: Buffer.from([1, 1, 1, 0]), // IHL=6
  });

  // 1. 小端 + 微秒：两个正常 UDP 包（第二个带 IPv4 选项）
  write("le-usec.pcap", pcap(true, false, [
    { sec: 1700000000, sub: 123456, data: frame1 },
    { sec: 1700000001, sub: 999999, data: frame2 },
  ]));

  // 2. 大端 + 纳秒：与 1 相同语义的帧，验证一致性
  write("be-nsec.pcap", pcap(false, true, [
    { sec: 1700000000, sub: 123456789, data: frame1 },
    { sec: 1700000001, sub: 999999999, data: frame2 },
  ]));

  // 3. snaplen 截短：incl_len < orig_len，UDP 载荷未完整捕获
  const full = buildFrame({ payload: Buffer.alloc(100, 0x41) });
  const captured = full.subarray(0, 60); // 截短到 60 字节
  write("snaplen-truncated.pcap", pcap(true, false, [
    { sec: 1700000100, sub: 1, data: captured, origLen: full.length },
  ], 60));

  // 4. 未支持协议：ARP (ethertype 0x0806)
  write("unsupported-arp.pcap", pcap(true, false, [
    { sec: 1700000200, sub: 0, data: buildFrame({ ethertype: 0x0806, payload: Buffer.alloc(28, 7) }) },
  ]));

  // 5. 空抓包（只有全局头）
  write("empty.pcap", globalHeader(true, false));

  // 6. 坏 magic
  const bad = Buffer.from(globalHeader(true, false));
  bad.writeUInt32LE(0xdeadbeef, 0);
  write("bad-magic.pcap", bad);

  // 7. 半个记录头
  write("half-record-header.pcap", Buffer.concat([
    globalHeader(true, false), recordHeader(true, 1, 2, 3, 4).subarray(0, 8),
  ]));

  // 8. 长度越界：声明 incl_len 大于文件剩余
  write("length-overrun.pcap", Buffer.concat([
    globalHeader(true, false),
    recordHeader(true, 1700000300, 0, 500, 500),
    frame1, // 实际只有一帧的字节，远小于 500
  ]));

  // 9. 非法子秒（微秒 >= 1e6）
  write("bad-subsec.pcap", Buffer.concat([
    globalHeader(true, false),
    recordHeader(true, 1700000400, 2_000_000, frame1.length, frame1.length),
    frame1,
  ]));

  // 10. IPv4 分片（MF=1）
  write("fragmented.pcap", pcap(true, false, [
    { sec: 1700000500, sub: 0, data: buildFrame({ flagsFragment: 0x2000, payload: Buffer.alloc(24, 0x42) }) },
  ]));

  // 11. Ethernet 尾部填充：IP total_length 之外的零填充不属于 UDP 载荷
  write("eth-padding.pcap", pcap(true, false, [
    { sec: 1700000600, sub: 500, data: buildFrame({ payload: Buffer.from("ab"), extraPadding: 18 }) },
  ]));

  // 12. UDP length 与 IP 矛盾
  write("udp-len-contradiction.pcap", pcap(true, false, [
    { sec: 1700000700, sub: 0, data: buildFrame({ payload: Buffer.from("xy"), udpLenOverride: 900, ipTotalOverride: 30 }) },
  ]));

  // 13. 时间戳倒退（顺序必须保持原样）
  write("out-of-order-ts.pcap", pcap(true, false, [
    { sec: 1700000800, sub: 0, data: frame1 },
    { sec: 1700000700, sub: 0, data: frame2 },
  ]));
}

if (process.argv[1] && process.argv[1].endsWith("make-fixtures.js")) main();


