import { createHash } from "node:crypto";
import { createReadStream, existsSync, lstatSync } from "node:fs";
import { chmod, mkdir, open, rename, rm } from "node:fs/promises";
import { dirname } from "node:path";

export interface PortableZipEntry {
  readonly name: string;
  readonly data?: string | Uint8Array;
  readonly filePath?: string;
}

export interface PortableZipResult {
  readonly destination: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly fileCount: number;
}

interface PreparedEntry {
  readonly name: string;
  readonly nameBytes: Buffer;
  readonly data?: Buffer;
  readonly filePath?: string;
  readonly size: number;
  readonly crc32: number;
}

const MAX_ZIP_32 = 0xffff_ffff;
const MAX_ENTRIES = 60_000;

const CRC_TABLE = (() => {
  const values = new Uint32Array(256);
  for (let index = 0; index < values.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? 0xedb8_8320 ^ (value >>> 1) : value >>> 1;
    }
    values[index] = value >>> 0;
  }
  return values;
})();

function updateCrc32(crc: number, bytes: Uint8Array): number {
  let value = crc;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff]! ^ (value >>> 8);
  return value >>> 0;
}

function safeArchiveName(value: string): string {
  if (!value.trim() || value.includes("\0") || value.startsWith("/") || value.includes("\\")) {
    throw new TypeError("ZIP entry name must be a safe relative path");
  }
  const segments = value.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new Error("ZIP entry path traversal is not permitted");
  }
  if (segments.some((segment) => [".obsidian", ".ti-scale"].includes(segment.toLowerCase()))) {
    throw new Error("Internal vault and Obsidian settings paths are excluded from portable exports");
  }
  return value;
}

async function crcAndSize(filePath: string): Promise<{ crc32: number; size: number }> {
  if (!existsSync(filePath) || lstatSync(filePath).isSymbolicLink() || !lstatSync(filePath).isFile()) {
    throw new Error("Portable ZIP source must be a regular non-symbolic-link file");
  }
  let crc = 0xffff_ffff;
  let size = 0;
  for await (const chunk of createReadStream(filePath, { highWaterMark: 64 * 1024 })) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > MAX_ZIP_32) throw new Error("Portable ZIP entry exceeds the ZIP32 size limit");
    crc = updateCrc32(crc, bytes);
  }
  return { crc32: (crc ^ 0xffff_ffff) >>> 0, size };
}

async function prepareEntry(entry: PortableZipEntry): Promise<PreparedEntry> {
  const name = safeArchiveName(entry.name);
  if ((entry.data === undefined) === (entry.filePath === undefined)) {
    throw new TypeError("ZIP entry requires exactly one data or filePath source");
  }
  const nameBytes = Buffer.from(name, "utf8");
  if (nameBytes.length > 0xffff) throw new Error("ZIP entry name is too long");
  if (entry.filePath) {
    const checked = await crcAndSize(entry.filePath);
    return { name, nameBytes, filePath: entry.filePath, ...checked };
  }
  const data = typeof entry.data === "string" ? Buffer.from(entry.data, "utf8") : Buffer.from(entry.data!);
  if (data.length > MAX_ZIP_32) throw new Error("Portable ZIP entry exceeds the ZIP32 size limit");
  return {
    name,
    nameBytes,
    data,
    size: data.length,
    crc32: (updateCrc32(0xffff_ffff, data) ^ 0xffff_ffff) >>> 0,
  };
}

function dosTimestamp(date: Date): { date: number; time: number } {
  const year = Math.max(1980, Math.min(2107, date.getUTCFullYear()));
  return {
    date: ((year - 1980) << 9) | ((date.getUTCMonth() + 1) << 5) | date.getUTCDate(),
    time: (date.getUTCHours() << 11) | (date.getUTCMinutes() << 5) | Math.floor(date.getUTCSeconds() / 2),
  };
}

function localHeader(entry: PreparedEntry, timestamp: ReturnType<typeof dosTimestamp>): Buffer {
  const header = Buffer.alloc(30 + entry.nameBytes.length);
  header.writeUInt32LE(0x0403_4b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(0x0800, 6);
  header.writeUInt16LE(0, 8);
  header.writeUInt16LE(timestamp.time, 10);
  header.writeUInt16LE(timestamp.date, 12);
  header.writeUInt32LE(entry.crc32, 14);
  header.writeUInt32LE(entry.size, 18);
  header.writeUInt32LE(entry.size, 22);
  header.writeUInt16LE(entry.nameBytes.length, 26);
  header.writeUInt16LE(0, 28);
  entry.nameBytes.copy(header, 30);
  return header;
}

function centralHeader(entry: PreparedEntry, offset: number, timestamp: ReturnType<typeof dosTimestamp>): Buffer {
  const header = Buffer.alloc(46 + entry.nameBytes.length);
  header.writeUInt32LE(0x0201_4b50, 0);
  header.writeUInt16LE(0x031e, 4);
  header.writeUInt16LE(20, 6);
  header.writeUInt16LE(0x0800, 8);
  header.writeUInt16LE(0, 10);
  header.writeUInt16LE(timestamp.time, 12);
  header.writeUInt16LE(timestamp.date, 14);
  header.writeUInt32LE(entry.crc32, 16);
  header.writeUInt32LE(entry.size, 20);
  header.writeUInt32LE(entry.size, 24);
  header.writeUInt16LE(entry.nameBytes.length, 28);
  header.writeUInt16LE(0, 30);
  header.writeUInt16LE(0, 32);
  header.writeUInt16LE(0, 34);
  header.writeUInt16LE(0, 36);
  header.writeUInt32LE(0, 38);
  header.writeUInt32LE(offset, 42);
  entry.nameBytes.copy(header, 46);
  return header;
}

function endRecord(count: number, centralSize: number, centralOffset: number): Buffer {
  const record = Buffer.alloc(22);
  record.writeUInt32LE(0x0605_4b50, 0);
  record.writeUInt16LE(0, 4);
  record.writeUInt16LE(0, 6);
  record.writeUInt16LE(count, 8);
  record.writeUInt16LE(count, 10);
  record.writeUInt32LE(centralSize, 12);
  record.writeUInt32LE(centralOffset, 16);
  record.writeUInt16LE(0, 20);
  return record;
}

/** Write a standards-compatible, UTF-8, store-mode ZIP atomically. */
export async function writePortableZip(
  entries: readonly PortableZipEntry[],
  destination: string,
  now = new Date(),
): Promise<PortableZipResult> {
  if (entries.length < 1 || entries.length > MAX_ENTRIES) {
    throw new Error(`Portable ZIP requires between 1 and ${MAX_ENTRIES} entries`);
  }
  const names = new Set<string>();
  const prepared: PreparedEntry[] = [];
  for (const entry of entries) {
    const item = await prepareEntry(entry);
    if (names.has(item.name)) throw new Error(`Duplicate portable ZIP entry: ${item.name}`);
    names.add(item.name);
    prepared.push(item);
  }

  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const temporary = `${destination}.tmp-${process.pid}-${Date.now()}`;
  const handle = await open(temporary, "wx", 0o600);
  const archiveHash = createHash("sha256");
  const central: Buffer[] = [];
  const timestamp = dosTimestamp(now);
  let offset = 0;
  const write = async (bytes: Uint8Array): Promise<void> => {
    const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    let written = 0;
    while (written < buffer.length) {
      const result = await handle.write(buffer, written, buffer.length - written, null);
      if (result.bytesWritten < 1) throw new Error("Portable ZIP write made no progress");
      written += result.bytesWritten;
    }
    archiveHash.update(buffer);
    offset += buffer.length;
    if (offset > MAX_ZIP_32) throw new Error("Portable ZIP exceeds the ZIP32 archive size limit");
  };

  try {
    for (const entry of prepared) {
      const entryOffset = offset;
      await write(localHeader(entry, timestamp));
      if (entry.data) await write(entry.data);
      else {
        for await (const chunk of createReadStream(entry.filePath!, { highWaterMark: 64 * 1024 })) {
          await write(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
      }
      central.push(centralHeader(entry, entryOffset, timestamp));
    }
    const centralOffset = offset;
    for (const header of central) await write(header);
    const centralSize = offset - centralOffset;
    await write(endRecord(prepared.length, centralSize, centralOffset));
    await handle.sync();
    await handle.close();
    await rename(temporary, destination);
    await chmod(destination, 0o600);
    return {
      destination,
      sha256: archiveHash.digest("hex"),
      byteSize: offset,
      fileCount: prepared.length,
    };
  } catch (error) {
    await handle.close().catch(() => undefined);
    await rm(temporary, { force: true });
    throw error;
  }
}
