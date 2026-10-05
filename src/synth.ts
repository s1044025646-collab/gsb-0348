/** Synthetic pcap fixture builders: hand-written byte layouts, used by scripts and tests. */

export interface SynthOpts {
  endianness?: "le" | "be";
  precision?: "micro" | "nano";
  snaplen?: number;
}

export function globalHeader(o: SynthOpts = {}): Buffer {
  const { endianness = "le", precision = "micro", snaplen = 65535 } = o;
  const magic =
    endianness === "le"
      ? precision === "micro" ? 0xa1b2c3d4 : 0xa1b23c4d
      : precision === "micro" ? 0xa1b2c3d4 : 0xa1b23c4d;
  const b = Buffer.alloc(24);
  if (endianness === "le") {
    b.writeUInt32LE(magic, 0);
    b.writeUInt16LE(2, 4); b.writeUInt16LE(4, 6);
    b.writeInt32LE(0, 8); b.writeUInt32LE(0, 12);
    b.writeUInt32LE(snaplen, 16); b.writeUInt32LE(1, 20);
  } else {
    b.writeUInt32BE(magic, 0);
    b.writeUInt16BE(2, 4); b.writeUInt16BE(4, 6);
    b.writeInt32BE(0, 8); b.writeUInt32BE(0, 12);
    b.writeUInt32BE(snaplen, 16); b.writeUInt32BE(1, 20);
  }
  return b;
}

export function recordHeader(
  o: SynthOpts, tsSec: number, tsFrac: number, inclLen: number, origLen: number
): Buffer {
  const le = (o.endianness ?? "le") === "le";
  const b = Buffer.alloc(16);
  if (le) {
    b.writeUInt32LE(tsSec, 0); b.writeUInt32LE(tsFrac, 4);
    b.writeUInt32LE(inclLen, 8); b.writeUInt32LE(origLen, 12);
  } else {
    b.writeUInt32BE(tsSec, 0); b.writeUInt32BE(tsFrac, 4);
    b.writeUInt32BE(inclLen, 8); b.writeUInt32BE(origLen, 12);
  }
  return b;
}

export interface UdpFrameOpts {
  srcMac?: string; dstMac?: string;
  srcIp?: string; dstIp?: string;
  srcPort?: number; dstPort?: number;
  payload?: Buffer;
  ipOptions?: Buffer; // multiple of 4 bytes
  ttl?: number;
  identification?: number;
  /** force IPv4 total length (otherwise computed) */
  ipTotalLength?: number;
  /** force UDP length field (otherwise computed) */
  udpLength?: number;
  /** IPv4 protocol field (default 17) */
  protocol?: number;
  /** set MF flag or fragment offset */
  fragField?: number;
  /** extra link-layer padding appended after IPv4 total length */
  padding?: number;
  etherType?: number;
}

function macBytes(s: string): number[] { return s.split(":").map((h) => parseInt(h, 16)); }
function ipBytes(s: string): number[] { return s.split(".").map((d) => parseInt(d, 10)); }

export function udpFrame(o: UdpFrameOpts = {}): Buffer {
  const payload = o.payload ?? Buffer.from("hello-udp");
  const ipOptions = o.ipOptions ?? Buffer.alloc(0);
  const ihl = 20 + ipOptions.length;
  const udpLen = o.udpLength ?? 8 + payload.length;
  const ipTotal = o.ipTotalLength ?? ihl + udpLen;
  const eth = Buffer.alloc(14);
  Buffer.from(macBytes(o.dstMac ?? "aa:bb:cc:dd:ee:ff")).copy(eth, 0);
  Buffer.from(macBytes(o.srcMac ?? "11:22:33:44:55:66")).copy(eth, 6);
  eth.writeUInt16BE(o.etherType ?? 0x0800, 12);
  const ip = Buffer.alloc(ihl);
  ip[0] = (4 << 4) | (ihl / 4);
  ip[1] = 0;
  ip.writeUInt16BE(ipTotal, 2);
  ip.writeUInt16BE(o.identification ?? 0x1234, 4);
  ip.writeUInt16BE(o.fragField ?? 0, 6);
  ip[8] = o.ttl ?? 64;
  ip[9] = o.protocol ?? 17;
  Buffer.from(ipBytes(o.srcIp ?? "192.168.0.1")).copy(ip, 12);
  Buffer.from(ipBytes(o.dstIp ?? "192.168.0.2")).copy(ip, 16);
  ipOptions.copy(ip, 20);
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(o.srcPort ?? 5000, 0);
  udp.writeUInt16BE(o.dstPort ?? 6000, 2);
  udp.writeUInt16BE(udpLen, 4);
  const frame = Buffer.concat([eth, ip, udp, payload]);
  if (o.padding) return Buffer.concat([frame, Buffer.alloc(o.padding, 0)]);
  return frame;
}

export function pcapFile(o: SynthOpts, records: { tsSec: number; tsFrac: number; data: Buffer; origLen?: number }[]): Buffer {
  const parts: Buffer[] = [globalHeader(o)];
  for (const r of records) {
    parts.push(recordHeader(o, r.tsSec, r.tsFrac, r.data.length, r.origLen ?? r.data.length));
    parts.push(r.data);
  }
  return Buffer.concat(parts);
}
