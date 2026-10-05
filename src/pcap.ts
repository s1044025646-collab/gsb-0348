/** Classic PCAP (libpcap) offline parser: Ethernet + IPv4 + UDP, byte-boundary safe. */

export const PCAP_GLOBAL_HEADER_LEN = 24;
export const PCAP_RECORD_HEADER_LEN = 16;
export const LINKTYPE_ETHERNET = 1;

export type Precision = "micro" | "nano";
export type Endianness = "le" | "be";

export interface Limits {
  maxFileBytes: number;
  maxPackets: number;
}

export const DEFAULT_LIMITS: Limits = {
  maxFileBytes: 64 * 1024 * 1024,
  maxPackets: 1_000_000,
};

export interface PcapDiagnostic {
  code: string;
  offset: number;
  recordIndex: number | null;
  message: string;
}

export type DecodeStatus =
  | "decoded" // UDP fields fully decoded
  | "undecoded" // unsupported/fragmented/etc, bytes summarized only
  | "truncated_capture" // snaplen cut headers/payload (incl_len < orig_len)
  | "inconsistent"; // fields contradict each other

export interface UdpInfo {
  srcPort: number;
  dstPort: number;
  length: number; // declared UDP length (header + payload)
  payloadLength: number; // declared payload bytes
  payloadCaptured: number; // actually readable payload bytes
  payloadOffset: number; // absolute file offset of payload start
  payloadHexPreview: string; // up to 32 bytes
}

export interface Ipv4Info {
  src: string;
  dst: string;
  ihl: number;
  totalLength: number;
  protocol: number;
  dscpEcn: number;
  identification: number;
  ttl: number;
  headerChecksum: number;
  optionsHex?: string;
}

export interface EthernetInfo {
  src: string;
  dst: string;
  etherType: number;
  paddingLength: number; // link-layer padding beyond IPv4 total length
}

export interface DecodeResult {
  status: DecodeStatus;
  reason?: string;
  ethernet?: EthernetInfo;
  ipv4?: Ipv4Info;
  udp?: UdpInfo;
  byteSummary: string; // first bytes hex, always available
}

export interface PacketRecord {
  index: number;
  offset: number; // absolute offset of record header
  dataOffset: number; // absolute offset of captured bytes
  tsSec: number;
  tsFrac: number;
  tsNs: string; // exact decimal nanoseconds since epoch
  inclLen: number;
  origLen: number;
  decode: DecodeResult;
}

export interface PcapParseResult {
  ok: boolean; // fully valid
  partial: boolean; // valid prefix parsed before a hard error
  endianness?: Endianness;
  precision?: Precision;
  versionMajor?: number;
  versionMinor?: number;
  snaplen?: number;
  linktype?: number;
  records: PacketRecord[];
  diagnostics: PcapDiagnostic[];
}

function hex(buf: Buffer, off: number, len: number): string {
  const end = Math.min(off + len, buf.length);
  if (off >= buf.length || len <= 0) return "";
  return buf.subarray(off, end).toString("hex");
}

function mac(buf: Buffer, off: number): string {
  return Array.from(buf.subarray(off, off + 6))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(":");
}

function ipv4Addr(buf: Buffer, off: number): string {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

export function tsToNsString(sec: number, frac: number, precision: Precision): string {
  const scale = precision === "nano" ? 1n : 1000n;
  return (BigInt(sec) * 1_000_000_000n + BigInt(frac) * scale).toString(10);
}

/** Decode one captured Ethernet frame. `cap` = captured bytes (incl_len), `orig` = orig_len. */
export function decodeEthernetFrame(frame: Buffer, capturedOrigLen: number): DecodeResult {
  const summary = hex(frame, 0, Math.min(32, frame.length));
  const res: DecodeResult = { status: "undecoded", byteSummary: summary };
  const truncated = frame.length < capturedOrigLen;
  const need = (n: number) => frame.length >= n;

  if (!need(14)) {
    res.status = truncated ? "truncated_capture" : "inconsistent";
    res.reason = truncated
      ? "capture truncated before end of Ethernet header"
      : "frame shorter than Ethernet header";
    return res;
  }
  const etherType = frame.readUInt16BE(12);
  res.ethernet = {
    dst: mac(frame, 0),
    src: mac(frame, 6),
    etherType,
    paddingLength: 0,
  };
  if (etherType !== 0x0800) {
    res.status = "undecoded";
    res.reason = `unsupported ethertype 0x${etherType.toString(16).padStart(4, "0")}`;
    return res;
  }
  // IPv4
  if (!need(14 + 20)) {
    res.status = truncated ? "truncated_capture" : "inconsistent";
    res.reason = truncated
      ? "capture truncated inside IPv4 header"
      : "frame shorter than minimal IPv4 header";
    return res;
  }
  const ip = 14;
  const version = frame[ip] >> 4;
  const ihl = (frame[ip] & 0x0f) * 4;
  if (version !== 4 || ihl < 20) {
    res.status = "inconsistent";
    res.reason = `invalid IPv4 version/IHL (version=${version}, ihl=${ihl})`;
    return res;
  }
  if (!need(ip + ihl)) {
    res.status = truncated ? "truncated_capture" : "inconsistent";
    res.reason = truncated
      ? "capture truncated inside IPv4 options"
      : "IHL exceeds captured frame";
    return res;
  }
  const totalLength = frame.readUInt16BE(ip + 2);
  if (totalLength < ihl) {
    res.status = "inconsistent";
    res.reason = `IPv4 total length ${totalLength} smaller than IHL ${ihl}`;
    return res;
  }
  const fragField = frame.readUInt16BE(ip + 6);
  const moreFragments = (fragField & 0x2000) !== 0;
  const fragOffset = fragField & 0x1fff;
  const protocol = frame[ip + 9];
  const optionsHex = ihl > 20 ? hex(frame, ip + 20, ihl - 20) : undefined;
  res.ipv4 = {
    src: ipv4Addr(frame, ip + 12),
    dst: ipv4Addr(frame, ip + 16),
    ihl,
    totalLength,
    protocol,
    dscpEcn: frame[ip + 1],
    identification: frame.readUInt16BE(ip + 4),
    ttl: frame[ip + 8],
    headerChecksum: frame.readUInt16BE(ip + 10),
    optionsHex,
  };
  // Link-layer padding: bytes beyond IPv4 total length inside the Ethernet frame.
  const ipEnd = ip + totalLength;
  if (frame.length > ipEnd) {
    res.ethernet.paddingLength = frame.length - ipEnd;
  }
  if (moreFragments || fragOffset !== 0) {
    res.status = "undecoded";
    res.reason = `fragmented IPv4 (mf=${moreFragments ? 1 : 0}, offset=${fragOffset})`;
    return res;
  }
  if (protocol !== 17) {
    res.status = "undecoded";
    res.reason = `unsupported IPv4 protocol ${protocol}`;
    return res;
  }
  // UDP header must lie within the IP-declared payload range.
  const udpOff = ip + ihl;
  const ipPayloadLen = totalLength - ihl;
  if (ipPayloadLen < 8) {
    res.status = "inconsistent";
    res.reason = `IPv4 payload ${ipPayloadLen} too small for UDP header`;
    return res;
  }
  if (!need(udpOff + 8)) {
    res.status = truncated ? "truncated_capture" : "inconsistent";
    res.reason = truncated
      ? "capture truncated inside UDP header"
      : "UDP header beyond captured frame";
    return res;
  }
  const srcPort = frame.readUInt16BE(udpOff);
  const dstPort = frame.readUInt16BE(udpOff + 2);
  const udpLen = frame.readUInt16BE(udpOff + 4);
  if (udpLen < 8) {
    res.status = "inconsistent";
    res.reason = `UDP length ${udpLen} smaller than header`;
    return res;
  }
  if (udpLen > ipPayloadLen) {
    res.status = "inconsistent";
    res.reason = `UDP length ${udpLen} exceeds IPv4 payload ${ipPayloadLen}`;
    return res;
  }
  const payloadDeclared = udpLen - 8;
  const payloadAvail = Math.max(0, Math.min(frame.length - (udpOff + 8), payloadDeclared));
  res.udp = {
    srcPort,
    dstPort,
    length: udpLen,
    payloadLength: payloadDeclared,
    payloadCaptured: payloadAvail,
    payloadOffset: udpOff + 8,
    payloadHexPreview: hex(frame, udpOff + 8, Math.min(32, payloadAvail)),
  };
  if (payloadAvail < payloadDeclared) {
    res.status = truncated ? "truncated_capture" : "inconsistent";
    res.reason = truncated
      ? `capture truncated UDP payload (${payloadAvail}/${payloadDeclared} bytes)`
      : "UDP payload shorter than declared length";
    return res;
  }
  res.status = "decoded";
  return res;
}

export function parsePcap(buf: Buffer, limits: Limits = DEFAULT_LIMITS): PcapParseResult {
  const diagnostics: PcapDiagnostic[] = [];
  const records: PacketRecord[] = [];
  const fail = (code: string, offset: number, recordIndex: number | null, message: string) => {
    diagnostics.push({ code, offset, recordIndex, message });
  };
  const result: PcapParseResult = { ok: false, partial: false, records, diagnostics };

  if (buf.length > limits.maxFileBytes) {
    fail("E_LIMIT_FILE_SIZE", 0, null, `file size ${buf.length} exceeds limit ${limits.maxFileBytes}`);
    return result;
  }
  if (buf.length < PCAP_GLOBAL_HEADER_LEN) {
    fail("E_TRUNCATED_GLOBAL_HEADER", 0, null, `global header needs 24 bytes, got ${buf.length}`);
    return result;
  }
  const magic = buf.readUInt32BE(0);
  let endianness: Endianness;
  let precision: Precision;
  if (magic === 0xa1b2c3d4) {
    endianness = "be";
    precision = "micro";
  } else if (magic === 0xd4c3b2a1) {
    endianness = "le";
    precision = "micro";
  } else if (magic === 0xa1b23c4d) {
    endianness = "be";
    precision = "nano";
  } else if (magic === 0x4d3cb2a1) {
    endianness = "le";
    precision = "nano";
  } else {
    fail("E_BAD_MAGIC", 0, null, `unknown magic 0x${magic.toString(16).padStart(8, "0")}`);
    return result;
  }
  const u16 = (off: number) =>
    endianness === "le" ? buf.readUInt16LE(off) : buf.readUInt16BE(off);
  const u32 = (off: number) =>
    endianness === "le" ? buf.readUInt32LE(off) : buf.readUInt32BE(off);

  const versionMajor = u16(4);
  const versionMinor = u16(6);
  const snaplen = u32(16);
  const linktype = u32(20) & 0xffff;
  result.endianness = endianness;
  result.precision = precision;
  result.versionMajor = versionMajor;
  result.versionMinor = versionMinor;
  result.snaplen = snaplen;
  result.linktype = linktype;

  if (versionMajor !== 2 || versionMinor !== 4) {
    fail("E_BAD_VERSION", 4, null, `unsupported version ${versionMajor}.${versionMinor}`);
    return result;
  }
  if (snaplen === 0) {
    fail("E_BAD_SNAPLEN", 16, null, "snaplen must be > 0");
    return result;
  }
  if (linktype !== LINKTYPE_ETHERNET) {
    fail("E_UNSUPPORTED_LINKTYPE", 20, null, `unsupported linktype ${linktype} (only Ethernet=1)`);
    return result;
  }
  const fracLimit = precision === "nano" ? 1_000_000_000 : 1_000_000;

  let offset = PCAP_GLOBAL_HEADER_LEN;
  let index = 0;
  while (offset < buf.length) {
    if (index >= limits.maxPackets) {
      fail("E_LIMIT_PACKETS", offset, index, `packet count exceeds limit ${limits.maxPackets}`);
      result.partial = records.length > 0;
      return result;
    }
    if (buf.length - offset < PCAP_RECORD_HEADER_LEN) {
      fail(
        "E_TRUNCATED_RECORD_HEADER",
        offset,
        index,
        `record header needs 16 bytes, only ${buf.length - offset} remain`
      );
      result.partial = records.length > 0;
      return result;
    }
    const tsSec = u32(offset);
    const tsFrac = u32(offset + 4);
    const inclLen = u32(offset + 8);
    const origLen = u32(offset + 12);
    if (tsFrac >= fracLimit) {
      fail(
        "E_BAD_SUBSECOND",
        offset + 4,
        index,
        `subsecond field ${tsFrac} out of range for ${precision} precision (limit ${fracLimit})`
      );
      result.partial = records.length > 0;
      return result;
    }
    if (inclLen > snaplen) {
      fail("E_INCL_GT_SNAPLEN", offset + 8, index, `incl_len ${inclLen} exceeds snaplen ${snaplen}`);
      result.partial = records.length > 0;
      return result;
    }
    if (inclLen > origLen) {
      fail("E_INCL_GT_ORIG", offset + 8, index, `incl_len ${inclLen} exceeds orig_len ${origLen}`);
      result.partial = records.length > 0;
      return result;
    }
    const dataOffset = offset + PCAP_RECORD_HEADER_LEN;
    if (buf.length - dataOffset < inclLen) {
      fail(
        "E_TRUNCATED_RECORD_DATA",
        dataOffset,
        index,
        `record declares ${inclLen} captured bytes, only ${buf.length - dataOffset} remain`
      );
      result.partial = records.length > 0;
      return result;
    }
    const frame = buf.subarray(dataOffset, dataOffset + inclLen);
    const decode = decodeEthernetFrame(frame, origLen);
    // udp payloadOffset is frame-relative; make it absolute.
    if (decode.udp) decode.udp.payloadOffset += dataOffset;
    records.push({
      index,
      offset,
      dataOffset,
      tsSec,
      tsFrac,
      tsNs: tsToNsString(tsSec, tsFrac, precision),
      inclLen,
      origLen,
      decode,
    });
    index++;
    offset = dataOffset + inclLen;
  }
  result.ok = true;
  return result;
}
