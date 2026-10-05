// 经典 PCAP 容器解析：全局头 + 逐条记录，严格维护声明长度与可读边界。
export type ByteOrder = "le" | "be";
export type SubsecPrecision = "micro" | "nano";

export interface GlobalHeader {
  byteOrder: ByteOrder;
  precision: SubsecPrecision;
  versionMajor: number;
  versionMinor: number;
  snaplen: number;
  network: number; // 仅支持 1 = Ethernet
  headerLength: number; // 固定 24
}

export interface PacketRecord {
  index: number; // 0 起，保持文件原顺序
  tsSec: number;
  tsSubsec: number;
  inclLen: number; // 文件中实际捕获的字节数
  origLen: number; // 线上原始长度
  headerOffset: number; // 记录头在文件中的偏移
  dataOffset: number; // 包数据在文件中的偏移
  data: Buffer; // 长度 === inclLen，绝不越界
}

export type DiagnosticCode =
  | "TRUNCATED_GLOBAL_HEADER"
  | "TRUNCATED_RECORD_HEADER"
  | "TRUNCATED_PACKET_DATA"
  | "SUBSECOND_OUT_OF_RANGE"
  | "INCL_LEN_EXCEEDS_SNAPLEN"
  | "INCL_LEN_EXCEEDS_ORIG_LEN";

export interface Diagnostic {
  code: DiagnosticCode;
  recordIndex: number | null; // 全局头问题为 null
  offset: number;
  message: string;
}

export interface ParseResult {
  header: GlobalHeader;
  records: PacketRecord[];
  diagnostics: Diagnostic[];
  /** 文件尾部存在截断（记录头或包数据不完整） */
  truncated: boolean;
}

const MAGIC_USEC_LE = 0xa1b2c3d4;
const MAGIC_USEC_BE = 0xd4c3b2a1;
const MAGIC_NSEC_LE = 0xa1b23c4d;
const MAGIC_NSEC_BE = 0x4d3cb2a1;

export const GLOBAL_HEADER_LEN = 24;
export const RECORD_HEADER_LEN = 16;
export const LINKTYPE_ETHERNET = 1;

export function parseGlobalHeader(buf: Buffer): GlobalHeader {
  if (buf.length < GLOBAL_HEADER_LEN) {
    throw new PcapFormatError(
      `全局头不完整：需要 ${GLOBAL_HEADER_LEN} 字节，实际 ${buf.length} 字节`,
      0
    );
  }
  const magic = buf.readUInt32LE(0);
  let byteOrder: ByteOrder;
  let precision: SubsecPrecision;
  if (magic === MAGIC_USEC_LE) { byteOrder = "le"; precision = "micro"; }
  else if (magic === MAGIC_USEC_BE) { byteOrder = "be"; precision = "micro"; }
  else if (magic === MAGIC_NSEC_LE) { byteOrder = "le"; precision = "nano"; }
  else if (magic === MAGIC_NSEC_BE) { byteOrder = "be"; precision = "nano"; }
  else {
    throw new PcapFormatError(
      `无法识别的 magic 0x${magic.toString(16).padStart(8, "0")}（不是经典 PCAP 或不支持的变体）`,
      0
    );
  }
  const u16 = (o: number) => byteOrder === "le" ? buf.readUInt16LE(o) : buf.readUInt16BE(o);
  const u32 = (o: number) => byteOrder === "le" ? buf.readUInt32LE(o) : buf.readUInt32BE(o);
  const versionMajor = u16(4);
  const versionMinor = u16(6);
  if (versionMajor !== 2 || versionMinor !== 4) {
    throw new PcapFormatError(`仅支持版本 2.4，实际 ${versionMajor}.${versionMinor}`, 4);
  }
  const snaplen = u32(16);
  const network = u32(20);
  if (snaplen === 0) {
    throw new PcapFormatError("snaplen 为 0，非法", 16);
  }
  if (network !== LINKTYPE_ETHERNET) {
    throw new PcapFormatError(`仅支持 Ethernet 链路类型(1)，实际 linktype=${network}`, 20);
  }
  return { byteOrder, precision, versionMajor, versionMinor, snaplen, network, headerLength: GLOBAL_HEADER_LEN };
}

export class PcapFormatError extends Error {
  constructor(message: string, public readonly offset: number) {
    super(message);
    this.name = "PcapFormatError";
  }
}

export function parsePcap(buf: Buffer, maxRecords: number): ParseResult {
  const header = parseGlobalHeader(buf);
  const u32 = (o: number) => header.byteOrder === "le" ? buf.readUInt32LE(o) : buf.readUInt32BE(o);
  const records: PacketRecord[] = [];
  const diagnostics: Diagnostic[] = [];
  let truncated = false;
  let offset = GLOBAL_HEADER_LEN;
  let index = 0;

  while (offset < buf.length) {
    if (index >= maxRecords) {
      throw new PcapFormatError(`记录数超过上限 ${maxRecords}`, offset);
    }
    const remaining = buf.length - offset;
    if (remaining < RECORD_HEADER_LEN) {
      diagnostics.push({
        code: "TRUNCATED_RECORD_HEADER",
        recordIndex: index,
        offset,
        message: `记录 #${index} 头部不完整：偏移 ${offset} 处仅剩 ${remaining} 字节（需要 ${RECORD_HEADER_LEN}）`,
      });
      truncated = true;
      break;
    }
    const tsSec = u32(offset);
    const tsSubsec = u32(offset + 4);
    const inclLen = u32(offset + 8);
    const origLen = u32(offset + 12);
    const dataOffset = offset + RECORD_HEADER_LEN;

    const subsecLimit = header.precision === "nano" ? 1_000_000_000 : 1_000_000;
    if (tsSubsec >= subsecLimit) {
      diagnostics.push({
        code: "SUBSECOND_OUT_OF_RANGE",
        recordIndex: index,
        offset: offset + 4,
        message: `记录 #${index} 子秒字段 ${tsSubsec} 超出 ${header.precision === "nano" ? "纳秒" : "微秒"}范围 [0, ${subsecLimit})`,
      });
    }
    if (inclLen > header.snaplen) {
      diagnostics.push({
        code: "INCL_LEN_EXCEEDS_SNAPLEN",
        recordIndex: index,
        offset: offset + 8,
        message: `记录 #${index} incl_len=${inclLen} 超过 snaplen=${header.snaplen}`,
      });
    }
    if (inclLen > origLen) {
      diagnostics.push({
        code: "INCL_LEN_EXCEEDS_ORIG_LEN",
        recordIndex: index,
        offset: offset + 8,
        message: `记录 #${index} incl_len=${inclLen} 大于 orig_len=${origLen}，字段自相矛盾`,
      });
    }
    if (dataOffset + inclLen > buf.length) {
      diagnostics.push({
        code: "TRUNCATED_PACKET_DATA",
        recordIndex: index,
        offset: dataOffset,
        message: `记录 #${index} 声明 incl_len=${inclLen}，但文件在偏移 ${dataOffset} 后仅剩 ${buf.length - dataOffset} 字节，容器被截断`,
      });
      truncated = true;
      break; // 不越界读取，不把后续字节当下一包
    }
    records.push({
      index, tsSec, tsSubsec, inclLen, origLen,
      headerOffset: offset, dataOffset,
      data: buf.subarray(dataOffset, dataOffset + inclLen),
    });
    offset = dataOffset + inclLen;
    index++;
  }
  return { header, records, diagnostics, truncated };
}

/** 将时间戳转换为精确十进制纳秒字符串（BigInt 运算，不经过浮点） */
export function timestampToNanoString(tsSec: number, tsSubsec: number, precision: SubsecPrecision): string {
  const sec = BigInt(tsSec);
  const sub = BigInt(tsSubsec);
  const nanos = precision === "nano" ? sub : sub * 1000n;
  return (sec * 1_000_000_000n + nanos).toString(10);
}
