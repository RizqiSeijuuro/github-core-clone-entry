// A small, dependency-free git object/pack/pkt-line implementation for the forge's smart-HTTP
// surface. Adapted (server side) from the kit's own conformance client (sdk/conformance/git-client.ts),
// which documents the exact wire format the suite drives: pkt-line framing, SHA-1 object hashing,
// tree/commit/tag encoding, and version-2 packfile read/write (including OFS_DELTA/REF_DELTA on read).
// Node built-ins only: node:crypto and node:zlib.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

export const ZERO_OID = '0'.repeat(40);
export const PKT_LINE_MAX_PAYLOAD = 65520 - 4;

export type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';
export interface GitObject { readonly type: GitObjectType; readonly data: Buffer; }
export interface TreeEntry { readonly mode: string; readonly name: string; readonly oid: string; }

const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const HEX40 = /^[0-9a-f]{40}$/;

export function isObjectId(v: string): boolean { return HEX40.test(v); }

export function hashObject(type: GitObjectType, data: Buffer): string {
  const h = createHash('sha1');
  h.update(`${type} ${data.length}\u0000`, 'utf8');
  h.update(data);
  return h.digest('hex');
}

// ---------------------------------------------------------------------- pkt-line

export function encodePktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.from((data.length + 4).toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, data]);
}
export function pktFlush(): Buffer { return Buffer.from('0000', 'ascii'); }
export function pktDelim(): Buffer { return Buffer.from('0001', 'ascii'); }

export function encodeLines(items: ReadonlyArray<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(encodePktLine(item));
  }
  return Buffer.concat(parts);
}

export type Packet = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' };

/** Decode a whole buffer of pkt-lines (the git smart-HTTP request bodies are small enough). */
export function decodePktLines(buf: Buffer): Packet[] {
  const out: Packet[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const header = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) break;
    const length = Number.parseInt(header, 16);
    if (length === 0) { out.push({ kind: 'flush' }); offset += 4; continue; }
    if (length === 1) { out.push({ kind: 'delim' }); offset += 4; continue; }
    if (length < 4) { offset += 4; continue; }
    if (offset + length > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return out;
}

// ---------------------------------------------------------------------- object model

export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    const mode = data.subarray(offset, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

export function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\u0000`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

export interface CommitView {
  tree: string; parents: string[]; author: string; committer: string; message: string;
}

export function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headerText = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let tree = ''; const parents: string[] = []; let author = ''; let committer = '';
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const value = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  return { tree, parents, author, committer, message };
}

export function buildCommit(fields: { tree: string; parents: string[]; message: string; author: string; committer: string }): Buffer {
  const lines = [`tree ${fields.tree}`];
  for (const p of fields.parents) lines.push(`parent ${p}`);
  lines.push(`author ${fields.author}`, `committer ${fields.committer}`, '');
  return Buffer.from(`${lines.join('\n')}\n${fields.message}`, 'utf8');
}

export interface TagView { object: string; type: GitObjectType; tag: string; tagger: string; message: string; }

export function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const headerText = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const headers = new Map<string, string>();
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    headers.set(line.slice(0, sp), line.slice(sp + 1));
  }
  return {
    object: headers.get('object') ?? '',
    type: (headers.get('type') ?? 'commit') as GitObjectType,
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message,
  };
}

// ---------------------------------------------------------------------- packfile read (v2, deltas supported)

function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start]; const first = byte; let size = byte & 0x0f; let shift = 4; let offset = start + 1;
  while (byte & 0x80) { byte = buf[offset++]; size += (byte & 0x7f) * 2 ** shift; shift += 7; }
  return { size, next: offset, first };
}

function readOfsBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buf[start]; let offset = start + 1; let value = byte & 0x7f;
  while (byte & 0x80) { byte = buf[offset++]; value = (value + 1) * 128 + (byte & 0x7f); }
  return { baseOffset: value, next: offset };
}

function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buf.subarray(offset);
  const result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  return { data: result.buffer, next: offset + result.engine.bytesWritten };
}

export function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let offset = 0;
  const readSize = (): number => {
    let value = 0; let shift = 0;
    for (;;) {
      const byte = delta[offset++];
      value += (byte & 0x7f) * 2 ** shift; shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize(); const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error(`delta base size mismatch: expected ${sourceSize}, got ${base.length}`);
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (offset < delta.length) {
    const op = delta[offset++];
    if (op & 0x80) {
      let copyOffset = 0, copySize = 0, shift = 0;
      for (let bit = 0; bit < 4; bit++) { if (op & (1 << bit)) { copyOffset += delta[offset++] * 2 ** shift; } shift += 8; }
      shift = 0;
      for (let bit = 4; bit < 7; bit++) { if (op & (1 << bit)) { copySize += delta[offset++] * 2 ** shift; } shift += 8; }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      delta.copy(out, written, offset, offset + op);
      offset += op; written += op;
    }
  }
  return out;
}

export interface PackReadResult { objects: Map<string, GitObject>; count: number; }

export function readPack(pack: Buffer): PackReadResult {
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  interface Raw { offset: number; typeCode: number; size: number; data: Buffer; baseOffset?: number; baseOid?: string; resolved?: Buffer; resolvedType?: GitObjectType; oid?: string; }
  const raw: Raw[] = []; const byOffset = new Map<number, Raw>();
  let offset = 12;
  for (let i = 0; i < declaredCount; i++) {
    const entryOffset = offset;
    const header = readVarintSize(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: Raw = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) { const b = readOfsBase(pack, offset); offset = b.next; entry.baseOffset = entryOffset - b.baseOffset; }
    else if (typeCode === 7) { entry.baseOid = pack.subarray(offset, offset + 20).toString('hex'); offset += 20; }
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    entry.data = inflated.data;
    offset = inflated.next;
    raw.push(entry); byOffset.set(entryOffset, entry);
  }
  const objects = new Map<string, GitObject>();
  const resolvedByOid = new Map<string, Raw>();
  const resolve = (entry: Raw): { type: GitObjectType; data: Buffer; oid: string } => {
    if (entry.resolved && entry.resolvedType && entry.oid) return { type: entry.resolvedType, data: entry.resolved, oid: entry.oid };
    let type: GitObjectType; let data: Buffer;
    if (entry.typeCode === 6) {
      const base = resolve(byOffset.get(entry.baseOffset!)!);
      type = base.type; data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const baseEntry = resolvedByOid.get(entry.baseOid!);
      const base = baseEntry ? resolve(baseEntry) : null;
      if (!base) throw new Error(`ref-delta base ${entry.baseOid} not found`);
      type = base.type; data = applyDelta(base.data, entry.data);
    } else {
      type = CODE_TYPE[entry.typeCode]; data = entry.data;
    }
    const oid = hashObject(type, data);
    entry.resolved = data; entry.resolvedType = type; entry.oid = oid;
    resolvedByOid.set(oid, entry);
    return { type, data, oid };
  };
  for (const entry of raw) {
    const r = resolve(entry);
    if (!objects.has(r.oid)) objects.set(r.oid, { type: r.type, data: r.data });
  }
  return { objects, count: declaredCount };
}

// ---------------------------------------------------------------------- packfile write (plain, no deltas)

function writeObjHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) { bytes.push(first | 0x80); first = remaining & 0x7f; remaining = Math.floor(remaining / 128); }
  bytes.push(first);
  return Buffer.from(bytes);
}

export function writePack(objects: GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) { parts.push(writeObjHeader(obj.type, obj.data.length)); parts.push(deflateSync(obj.data)); }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}
