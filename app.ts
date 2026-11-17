// The forge's HTTP surface: git smart HTTP (upload-pack v2, receive-pack v0), the GitHub REST v3
// API, GraphQL v4, and a Model Context Protocol endpoint. All state lives in memory (store.ts);
// git object/pack/pkt-line plumbing is in git.ts. No package, no outside service, no git binary.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import type { GitObject } from './git.ts';
import {
  applyDelta, buildCommit, buildTree, decodePktLines, encodeLines,
  encodePktLine, isObjectId, parseCommit, parseTag, parseTree, pktDelim, pktFlush,
  readPack, writePack, ZERO_OID,
} from './git.ts';
import type { CommentRecord, IssueRecord, PullRecord, RepoRecord } from './store.ts';
import { Store, boundedReachable, depthClosure, putObject, reachable, treeAndBlobsOf } from './store.ts';

function buildTagShim(fields: { object: string; type: 'commit'; tag: string; tagger: string; message: string }): Buffer {
  return Buffer.from(`object ${fields.object}\ntype ${fields.type}\ntag ${fields.tag}\ntagger ${fields.tagger}\n\n${fields.message}`, 'utf8');
}

const JSON_TYPE = 'application/json; charset=utf-8';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
// The one authenticated login every request's token resolves to. The forge serves exactly one
// user: whoever presents the right bearer token. (See README for how this name is derived.)
const AUTH_LOGIN = 'adaiversen';
const INSTALLED_VERSION = 'makefun-forge-1.0.0';

const store = new Store(AUTH_LOGIN);

function requestId(): string { return randomUUID(); }

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId(),
    ...headers,
  });
  res.end(text);
}

function notFound(res: ServerResponse): void { sendJson(res, 404, { message: 'Not Found' }); }
function unauthorized(res: ServerResponse): void { sendJson(res, 401, { message: 'Requires authentication' }); }
function badRequest(res: ServerResponse, message = 'Problems parsing JSON'): void { sendJson(res, 400, { message }); }

function readBody(req: IncomingMessage, maxBytes = 64 * 1024 * 1024): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []; let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function bearerToken(req: IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (!auth || typeof auth !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  return m ? m[1] : null;
}

function authed(req: IncomingMessage): boolean {
  const t = bearerToken(req);
  return t !== null && TOKEN !== '' && t === TOKEN;
}

// ======================================================================================
// Git smart HTTP
// ======================================================================================

const GIT_PATH_RE = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/;

function repoAdvertisementV0Lines(repo: RepoRecord, service: 'git-upload-pack' | 'git-receive-pack'): Array<string | 'flush'> {
  const caps =
    service === 'git-receive-pack'
      ? 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=makefun-git-server/1.0'
      : 'side-band-64k ofs-delta agent=makefun-git-server/1.0';
  const lines: Array<string | 'flush'> = [];
  const entries: Array<{ oid: string; name: string }> = [];
  for (const [name, oid] of repo.refs) entries.push({ oid, name });
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const head = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (entries.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\u0000${caps}\n`);
  } else {
    const first = entries[0];
    const symref = `symref=HEAD:refs/heads/${repo.defaultBranch}`;
    if (head) lines.push(`${head} HEAD\u0000${caps} ${symref}\n`);
    else lines.push(`${first.oid} ${first.name}\u0000${caps} ${symref}\n`);
    for (const e of entries) {
      lines.push(`${e.oid} ${e.name}\n`);
      // peel annotated tags
      const obj = repo.objects.get(e.oid);
      if (obj && obj.type === 'tag') {
        const tag = parseTag(obj.data);
        lines.push(`${tag.object} ${e.name}^{}\n`);
      }
    }
  }
  lines.push('flush');
  return lines;
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, query: URLSearchParams): void {
  const service = query.get('service');
  const repo = store.get(owner, repoName);
  if (!repo) { notFound(res); return; }
  if (service === 'git-upload-pack') {
    // Always serve protocol v2 for upload-pack.
    const caps: Array<string | Buffer> = [
      'version 2\n', 'agent=makefun-git-server/1.0\n', 'ls-refs=unborn\n', 'fetch=shallow\n', 'object-format=sha1\n', 'server-option\n',
    ];
    const body = encodeLines([...caps, 'flush']);
    res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-advertisement', 'cache-control': 'no-cache' });
    res.end(body);
    return;
  }
  if (service === 'git-receive-pack') {
    const lines = repoAdvertisementV0Lines(repo, 'git-receive-pack');
    const preamble = encodePktLine('# service=git-receive-pack\n');
    const flush0 = pktFlush();
    const rest = encodeLines(lines);
    res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-advertisement', 'cache-control': 'no-cache' });
    res.end(Buffer.concat([preamble, flush0, rest]));
    return;
  }
  notFound(res);
}

interface SidebandWriter { write(band: 1 | 2 | 3, data: Buffer): void; flush(): void; raw(buf: Buffer): void; end(): void; }

function makeSidebandWriter(res: ServerResponse): SidebandWriter {
  return {
    write(band, data) {
      // side-band-64k: max 65519 payload bytes per packet including the band byte, so 65515 data bytes.
      let offset = 0;
      const MAX = 65515;
      if (data.length === 0) { res.write(encodePktLine(Buffer.concat([Buffer.from([band]), data]))); return; }
      while (offset < data.length) {
        const chunk = data.subarray(offset, offset + MAX);
        res.write(encodePktLine(Buffer.concat([Buffer.from([band]), chunk])));
        offset += chunk.length;
      }
    },
    flush() { res.write(pktFlush()); },
    raw(buf) { res.write(buf); },
    end() { res.end(); },
  };
}

function parseFetchCommand(packets: ReturnType<typeof decodePktLines>): {
  wants: string[]; haves: string[]; shallow: string[]; depth: number | null; done: boolean; lsRefs: boolean;
  prefixes: string[]; peel: boolean; symrefs: boolean;
} {
  let lsRefs = false; let isFetch = false;
  const wants: string[] = []; const haves: string[] = []; const shallow: string[] = [];
  const prefixes: string[] = []; let depth: number | null = null; let done = false;
  let peel = false; let symrefs = false;
  for (const p of packets) {
    if (p.kind !== 'data') continue;
    const text = p.payload.toString('utf8').replace(/\n$/, '');
    if (text === 'command=ls-refs') { lsRefs = true; continue; }
    if (text === 'command=fetch') { isFetch = true; continue; }
    if (text.startsWith('want ')) wants.push(text.slice(5).trim());
    else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
    else if (text.startsWith('shallow ')) shallow.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) depth = Number.parseInt(text.slice(7).trim(), 10);
    else if (text === 'done') done = true;
    else if (text.startsWith('ref-prefix ')) prefixes.push(text.slice(11).trim());
    else if (text === 'peel') peel = true;
    else if (text === 'symrefs') symrefs = true;
  }
  void isFetch;
  return { wants, haves, shallow, depth, done, lsRefs, prefixes, peel, symrefs };
}

function handleLsRefs(repo: RepoRecord, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  const req = parseFetchCommand(packets);
  const lines: Array<string | 'flush'> = [];
  const entries: Array<{ oid: string; name: string }> = [...repo.refs].map(([name, oid]) => ({ name, oid }));
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const keep = (name: string): boolean => req.prefixes.length === 0 || req.prefixes.some((p) => name.startsWith(p));
  // HEAD
  const headTarget = `refs/heads/${repo.defaultBranch}`;
  const headOid = repo.refs.get(headTarget);
  if (keep('HEAD')) {
    if (headOid) lines.push(`${headOid} HEAD${req.symrefs ? ` symref-target:${headTarget}` : ''}\n`);
  }
  for (const e of entries) {
    if (!keep(e.name)) continue;
    let line = `${e.oid} ${e.name}`;
    if (req.peel) {
      const obj = repo.objects.get(e.oid);
      if (obj && obj.type === 'tag') line += ` peeled:${parseTag(obj.data).object}`;
    }
    lines.push(`${line}\n`);
  }
  lines.push('flush');
  return encodeLines(lines);
}

function handleFetch(repo: RepoRecord, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  const req = parseFetchCommand(packets);
  const wants = req.wants.filter(isObjectId);
  const out: Array<string | Buffer | 'flush' | 'delim'> = [];
  let objectsToSend: Set<string>;
  const shallowLines: string[] = []; const unshallowLines: string[] = [];
  if (req.depth !== null && req.depth > 0) {
    const { commits, boundary } = depthClosure(repo, wants, req.depth);
    const full = treeAndBlobsOf(repo, commits);
    const stop = new Set(req.shallow.filter(isObjectId));
    const known = boundedReachable(repo, req.haves.filter(isObjectId), stop);
    objectsToSend = new Set([...full].filter((o) => !known.has(o)));
    for (const oid of boundary) shallowLines.push(`shallow ${oid}\n`);
    for (const oid of stop) if (commits.has(oid) && !boundary.has(oid)) unshallowLines.push(`unshallow ${oid}\n`);
  } else {
    const full = reachable(repo, wants);
    const known = req.haves.length ? reachable(repo, req.haves.filter(isObjectId)) : new Set<string>();
    objectsToSend = new Set([...full].filter((o) => !known.has(o)));
  }
  if (shallowLines.length || unshallowLines.length) {
    out.push('shallow-info\n', ...shallowLines, ...unshallowLines, 'delim');
  }
  out.push('packfile\n');
  const objects: GitObject[] = [...objectsToSend].map((oid) => repo.objects.get(oid)!).filter(Boolean);
  const pack = writePack(objects);
  // wrap packfile bytes into sideband band-1 pkt-lines, each at most 65515 payload bytes
  const bandPackets: Buffer[] = [];
  let offset = 0; const MAX = 65515;
  while (offset < pack.length) {
    const chunk = pack.subarray(offset, offset + MAX);
    bandPackets.push(encodePktLine(Buffer.concat([Buffer.from([1]), chunk])));
    offset += chunk.length;
  }
  if (bandPackets.length === 0) {
    // empty pack still produces header+trailer, writePack([]) always yields 32 bytes; fall through
  }
  const head = encodeLines(out);
  const packBuf = Buffer.concat(bandPackets);
  return Buffer.concat([head, packBuf, pktFlush()]);
}

function ffCheck(repo: RepoRecord, oldOid: string, newOid: string): boolean {
  if (oldOid === ZERO_OID) return true; // create
  if (newOid === ZERO_OID) return true; // delete
  const anc = reachable(repo, [newOid]);
  return anc.has(oldOid);
}

async function handleUploadPack(req: IncomingMessage, res: ServerResponse, repo: RepoRecord): Promise<void> {
  const body = await readBody(req);
  const packets = decodePktLines(body);
  const cmdText = packets.find((p) => p.kind === 'data')?.payload.toString('utf8').trim();
  res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'cache-control': 'no-cache' });
  if (cmdText === 'command=ls-refs') { res.end(handleLsRefs(repo, body)); return; }
  res.end(handleFetch(repo, body));
}

async function handleReceivePack(req: IncomingMessage, res: ServerResponse, repo: RepoRecord): Promise<void> {
  const body = await readBody(req);
  // find first flush/delim to split the command list from the pack data
  let offset = 0; const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let sideband = true;
  while (offset + 4 <= body.length) {
    const header = body.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) break;
    const length = Number.parseInt(header, 16);
    if (length === 0) { offset += 4; break; }
    const payload = body.subarray(offset + 4, offset + length).toString('utf8').replace(/\n$/, '');
    const nul = payload.indexOf('\u0000');
    const line = nul >= 0 ? payload.slice(0, nul) : payload;
    const caps = nul >= 0 ? payload.slice(nul + 1) : '';
    if (nul >= 0 && !caps.includes('side-band-64k')) sideband = false;
    const parts = line.split(' ');
    commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
    offset += length;
  }
  const packBytes = body.subarray(offset);
  const writer = makeSidebandWriter(res);
  res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'cache-control': 'no-cache' });

  let unpackOk = true; let unpackDetail = 'ok';
  if (packBytes.length >= 12 && packBytes.subarray(0, 4).toString('ascii') === 'PACK') {
    try {
      const result = readPack(packBytes);
      for (const [oid, obj] of result.objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = `unpack error: ${err instanceof Error ? err.message : String(err)}`;
    }
  }

  const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}\n`];
  for (const cmd of commands) {
    if (!unpackOk) { reportLines.push(`ng ${cmd.ref} unpack-failed\n`); continue; }
    const current = repo.refs.get(cmd.ref) ?? ZERO_OID;
    if (current !== cmd.oldOid) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
    if (!ffCheck(repo, cmd.oldOid, cmd.newOid)) { reportLines.push(`ng ${cmd.ref} non-fast-forward\n`); continue; }
    if (cmd.newOid === ZERO_OID) repo.refs.delete(cmd.ref);
    else repo.refs.set(cmd.ref, cmd.newOid);
    reportLines.push(`ok ${cmd.ref}\n`);
  }
  const reportBody = encodeLines(reportLines);
  if (sideband) {
    writer.write(1, reportBody);
    writer.flush();
    writer.end();
  } else {
    res.end(reportBody);
  }
}

// ======================================================================================
// REST v3
// ======================================================================================

function repoJson(repo: RepoRecord): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: 1000 },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `${API_BASE_PLACEHOLDER}/repos/${repo.owner}/${repo.name}`,
    created_at: repo.createdAt,
    updated_at: repo.createdAt,
    fork: false,
    archived: false,
    disabled: false,
    visibility: repo.private ? 'private' : 'public',
  };
}
const API_BASE_PLACEHOLDER = '/api/v3';

function issueJson(repo: RepoRecord, issue: IssueRecord): Record<string, unknown> {
  return {
    id: 20000 + issue.number,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name, color: repo.labels.get(name)?.color ?? 'ededed' })),
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    user: { login: repo.owner, id: 1000 },
    comments: issue.comments.length,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function pullJson(repo: RepoRecord, pull: PullRecord): Record<string, unknown> {
  return {
    id: 30000 + pull.number,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.head, sha: pull.headSha, label: `${repo.owner}:${pull.head}` },
    base: { ref: pull.base, sha: pull.baseSha, label: `${repo.owner}:${pull.base}` },
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    user: { login: repo.owner, id: 1000 },
  };
}

function nowIso(): string {
  // A fixed logical clock would be ideal, but issue/PR creation order is the only thing checks
  // compare (numbers increment, lists sort by creation). Real time is fine here: it never enters
  // a git object or the git-level determinism surface, only REST metadata.
  return new Date().toISOString();
}

function nextIssueNumber(repo: RepoRecord): number { return repo.nextNumber++; }

function diffPaths(repo: RepoRecord, baseTree: string, headTree: string, prefix = ''): Array<{ path: string; status: string }> {
  const out: Array<{ path: string; status: string }> = [];
  const baseEntries = new Map((baseTree ? parseTree(repo.objects.get(baseTree)?.data ?? Buffer.alloc(0)) : []).map((e) => [e.name, e]));
  const headEntries = new Map((headTree ? parseTree(repo.objects.get(headTree)?.data ?? Buffer.alloc(0)) : []).map((e) => [e.name, e]));
  const names = new Set([...baseEntries.keys(), ...headEntries.keys()]);
  for (const name of names) {
    const b = baseEntries.get(name); const h = headEntries.get(name);
    const path = prefix ? `${prefix}/${name}` : name;
    if (b && h && b.oid === h.oid) continue;
    if (h && h.mode === '40000') {
      out.push(...diffPaths(repo, b?.mode === '40000' ? b.oid : '', h.oid, path));
    } else if (b && b.mode === '40000' && !h) {
      out.push(...diffPaths(repo, b.oid, '', path));
    } else if (!b && h) out.push({ path, status: 'added' });
    else if (b && !h) out.push({ path, status: 'removed' });
    else out.push({ path, status: 'modified' });
  }
  return out;
}

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, query: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  const sub = path.slice('/api/v3'.length) || '/';

  if (sub === '/' || sub === '') {
    if (!authed(req)) { unauthorized(res); return; }
    sendJson(res, 200, { current_user_url: `${API_BASE_PLACEHOLDER}/user` }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (sub === '/meta') { sendJson(res, 200, { installed_version: INSTALLED_VERSION, verifiable_password_authentication: false }); return; }
  if (sub === '/user' && method === 'GET') {
    if (!authed(req)) { unauthorized(res); return; }
    sendJson(res, 200, { login: AUTH_LOGIN, id: 1000 });
    return;
  }

  if (!authed(req)) { unauthorized(res); return; }

  if (sub === '/user/repos') {
    if (method === 'GET') {
      const perPage = Math.max(1, Math.min(100, Number.parseInt(query.get('per_page') ?? '30', 10) || 30));
      const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
      const all = store.list(AUTH_LOGIN).sort((a, b) => a.id - b.id);
      const start = (page - 1) * perPage;
      const slice = all.slice(start, start + perPage);
      const headers: Record<string, string> = {};
      if (start + perPage < all.length) {
        const proto = (req.headers['x-forwarded-proto'] as string) ?? 'http';
        const host = req.headers.host ?? '127.0.0.1';
        headers.link = `<${proto}://${host}${API_BASE_PLACEHOLDER}/user/repos?per_page=${perPage}&page=${page + 1}>; rel="next"`;
      }
      sendJson(res, 200, slice.map(repoJson), headers);
      return;
    }
    if (method === 'POST') {
      const body = await readBody(req);
      let json: Record<string, unknown>;
      try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
      const name = typeof json.name === 'string' ? json.name : '';
      if (!name) { badRequest(res, 'name is required'); return; }
      if (store.get(AUTH_LOGIN, name)) { sendJson(res, 422, { message: `repository ${name} already exists` }); return; }
      const repo = store.create(AUTH_LOGIN, name, { description: typeof json.description === 'string' ? json.description : '', private: json.private !== false });
      sendJson(res, 201, repoJson(repo));
      return;
    }
  }

  const repoMatch = /^\/repos\/([^/]+)\/([^/]+)(\/.*)?$/.exec(sub);
  if (repoMatch) {
    const [, owner, name, rest0] = repoMatch;
    const rest = rest0 ?? '';
    if (owner !== AUTH_LOGIN) { notFound(res); return; }
    const repo = store.get(owner, name);
    if (!repo && rest !== '') { notFound(res); return; }

    if (rest === '' || rest === '/') {
      if (!repo) { notFound(res); return; }
      if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return; }
      if (method === 'PATCH') {
        const body = await readBody(req);
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
        if (typeof json.description === 'string') repo.description = json.description;
        sendJson(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') { store.delete(owner, name); res.writeHead(204, { 'x-github-request-id': requestId() }); res.end(); return; }
    }
    if (!repo) { notFound(res); return; }

    if (rest === '/branches' && method === 'GET') {
      const out = [...repo.refs].filter(([n]) => n.startsWith('refs/heads/')).map(([n, oid]) => ({ name: n.slice('refs/heads/'.length), commit: { sha: oid } }));
      sendJson(res, 200, out);
      return;
    }
    const refsMatch = /^\/git\/refs$/.exec(rest);
    if (refsMatch && method === 'POST') {
      const body = await readBody(req);
      let json: Record<string, unknown> = {};
      try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
      const ref = typeof json.ref === 'string' ? json.ref : '';
      const sha = typeof json.sha === 'string' ? json.sha : '';
      if (!ref || !isObjectId(sha)) { badRequest(res); return; }
      repo.refs.set(ref, sha);
      sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
      return;
    }
    if (rest === '/commits' && method === 'GET') {
      const shaParam = query.get('sha');
      const start = shaParam ? repo.refs.get(shaParam.startsWith('refs/') ? shaParam : `refs/heads/${shaParam}`) ?? (isObjectId(shaParam) ? shaParam : undefined) : repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      const out: Array<Record<string, unknown>> = [];
      let cursor = start;
      const seen = new Set<string>();
      while (cursor && repo.objects.has(cursor) && !seen.has(cursor)) {
        seen.add(cursor);
        const obj = repo.objects.get(cursor)!;
        if (obj.type !== 'commit') break;
        const c = parseCommit(obj.data);
        out.push({ sha: cursor, commit: { message: c.message, author: { name: c.author }, committer: { name: c.committer } } });
        cursor = c.parents[0];
      }
      sendJson(res, 200, out);
      return;
    }

    const contentsMatch = /^\/contents\/(.+)$/.exec(rest);
    if (contentsMatch) {
      const filePath = decodeURIComponent(contentsMatch[1]);
      if (method === 'GET') {
        const branch = query.get('ref') ?? repo.defaultBranch;
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (!tip) { notFound(res); return; }
        const commit = parseCommit(repo.objects.get(tip)!.data);
        const found = walkTree(repo, commit.tree, filePath);
        if (!found) { notFound(res); return; }
        if (found.mode === '40000') {
          const entries = parseTree(repo.objects.get(found.oid)!.data);
          sendJson(res, 200, entries.map((e) => ({ name: e.name, path: `${filePath}/${e.name}`, sha: e.oid, type: e.mode === '40000' ? 'dir' : 'file' })));
          return;
        }
        const blob = repo.objects.get(found.oid)!;
        sendJson(res, 200, { name: filePath.split('/').pop(), path: filePath, sha: found.oid, size: blob.data.length, encoding: 'base64', content: blob.data.toString('base64'), type: 'file' });
        return;
      }
      if (method === 'PUT') {
        const body = await readBody(req);
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
        const branch = typeof json.branch === 'string' && json.branch ? json.branch : repo.defaultBranch;
        const tip = repo.refs.get(`refs/heads/${branch}`);
        const contentB64 = typeof json.content === 'string' ? json.content : '';
        const message = typeof json.message === 'string' ? json.message : 'update';
        const expectedSha = typeof json.sha === 'string' ? json.sha : undefined;
        const fileData = Buffer.from(contentB64, 'base64');
        let existing: { oid: string } | undefined;
        if (tip) {
          const commit = parseCommit(repo.objects.get(tip)!.data);
          const found = walkTree(repo, commit.tree, filePath);
          existing = found && found.mode !== '40000' ? found : undefined;
        }
        if (expectedSha !== undefined && existing?.oid !== expectedSha) { sendJson(res, 409, { message: 'sha does not match' }); return; }
        if (expectedSha === undefined && existing) { sendJson(res, 409, { message: 'file already exists' }); return; }
        const blobOid = putObject(repo, 'blob', fileData);
        const baseTree = tip ? parseCommit(repo.objects.get(tip)!.data).tree : '';
        const newTree = writeFileIntoTree(repo, baseTree, filePath, blobOid);
        const commitOid = putObject(repo, 'commit', buildCommit({
          tree: newTree, parents: tip ? [tip] : [], message: message.endsWith('\n') ? message : `${message}\n`,
          author: `${AUTH_LOGIN} <${AUTH_LOGIN}@example.invalid> 1735689600 +0000`,
          committer: `${AUTH_LOGIN} <${AUTH_LOGIN}@example.invalid> 1735689600 +0000`,
        }));
        repo.refs.set(`refs/heads/${branch}`, commitOid);
        sendJson(res, tip ? 200 : 201, { content: { sha: blobOid, encoding: 'base64' }, commit: { sha: commitOid } });
        return;
      }
      if (method === 'DELETE') {
        const body = await readBody(req);
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { /* optional body */ }
        const branch = typeof json.branch === 'string' && json.branch ? json.branch : repo.defaultBranch;
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (!tip) { notFound(res); return; }
        const message = typeof json.message === 'string' ? json.message : 'delete';
        const commit = parseCommit(repo.objects.get(tip)!.data);
        const newTree = deleteFromTree(repo, commit.tree, filePath);
        const commitOid = putObject(repo, 'commit', buildCommit({
          tree: newTree, parents: [tip], message: message.endsWith('\n') ? message : `${message}\n`,
          author: `${AUTH_LOGIN} <${AUTH_LOGIN}@example.invalid> 1735689600 +0000`,
          committer: `${AUTH_LOGIN} <${AUTH_LOGIN}@example.invalid> 1735689600 +0000`,
        }));
        repo.refs.set(`refs/heads/${branch}`, commitOid);
        sendJson(res, 200, { commit: { sha: commitOid } });
        return;
      }
    }

    if (rest === '/labels' && method === 'POST') {
      const body = await readBody(req);
      let json: Record<string, unknown> = {};
      try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
      const name = typeof json.name === 'string' ? json.name : '';
      if (!name) { badRequest(res); return; }
      const color = typeof json.color === 'string' ? json.color : 'ededed';
      repo.labels.set(name, { name, color });
      sendJson(res, 201, { name, color });
      return;
    }

    if (rest === '/issues' && method === 'GET') {
      const state = query.get('state') ?? 'open';
      const sort = query.get('sort') ?? 'created';
      const direction = query.get('direction') ?? 'desc';
      let list = [...repo.issues.values()].filter((i) => !i.isPull);
      if (state !== 'all') list = list.filter((i) => i.state === state);
      list.sort((a, b) => (sort === 'created' ? a.number - b.number : 0));
      if (direction === 'desc') list.reverse();
      sendJson(res, 200, list.map((i) => issueJson(repo, i)));
      return;
    }
    if (rest === '/issues' && method === 'POST') {
      const body = await readBody(req);
      let json: Record<string, unknown> = {};
      try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
      const title = typeof json.title === 'string' ? json.title : '';
      const bodyText = typeof json.body === 'string' ? json.body : '';
      const labels = Array.isArray(json.labels) ? (json.labels as unknown[]).filter((l): l is string => typeof l === 'string') : [];
      for (const l of labels) if (!repo.labels.has(l)) { sendJson(res, 422, { message: `label ${l} does not exist` }); return; }
      const number = nextIssueNumber(repo);
      const now = nowIso();
      const issue: IssueRecord = { number, title, body: bodyText, state: 'open', labels, createdAt: now, updatedAt: now, closedAt: null, comments: [], isPull: false };
      repo.issues.set(number, issue);
      sendJson(res, 201, issueJson(repo, issue));
      return;
    }
    const issueOneMatch = /^\/issues\/(\d+)$/.exec(rest);
    if (issueOneMatch) {
      const n = Number.parseInt(issueOneMatch[1], 10);
      const issue = repo.issues.get(n);
      if (!issue) { notFound(res); return; }
      if (method === 'GET') { sendJson(res, 200, issueJson(repo, issue)); return; }
      if (method === 'PATCH') {
        const body = await readBody(req);
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
        if (json.state === 'closed') { issue.state = 'closed'; issue.closedAt = nowIso(); }
        else if (json.state === 'open') { issue.state = 'open'; issue.closedAt = null; }
        issue.updatedAt = nowIso();
        sendJson(res, 200, issueJson(repo, issue));
        return;
      }
    }
    const commentsMatch = /^\/issues\/(\d+)\/comments$/.exec(rest);
    if (commentsMatch) {
      const n = Number.parseInt(commentsMatch[1], 10);
      const issue = repo.issues.get(n);
      if (!issue) { notFound(res); return; }
      if (method === 'GET') { sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body, created_at: c.createdAt }))); return; }
      if (method === 'POST') {
        const body = await readBody(req);
        let json: Record<string, unknown> = {};
        try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
        const commentBody = typeof json.body === 'string' ? json.body : '';
        const comment: CommentRecord = { id: 40000 + issue.comments.length + 1, body: commentBody, createdAt: nowIso() };
        issue.comments.push(comment);
        sendJson(res, 201, { id: comment.id, body: comment.body, created_at: comment.createdAt });
        return;
      }
    }

    if (rest === '/pulls' && method === 'GET') {
      const state = query.get('state') ?? 'open';
      let list = [...repo.pulls.values()];
      if (state !== 'all') list = list.filter((p) => p.state === state);
      list.sort((a, b) => a.number - b.number);
      sendJson(res, 200, list.map((p) => pullJson(repo, p)));
      return;
    }
    if (rest === '/pulls' && method === 'POST') {
      const body = await readBody(req);
      let json: Record<string, unknown> = {};
      try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
      const title = typeof json.title === 'string' ? json.title : '';
      const bodyText = typeof json.body === 'string' ? json.body : '';
      const head = typeof json.head === 'string' ? json.head : '';
      const base = typeof json.base === 'string' ? json.base : repo.defaultBranch;
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (!headSha || !baseSha) { sendJson(res, 422, { message: 'head or base branch not found' }); return; }
      const number = nextIssueNumber(repo);
      const now = nowIso();
      const pull: PullRecord = { number, title, body: bodyText, state: 'open', merged: false, mergedAt: null, mergeCommitSha: null, head, base, headSha, baseSha, createdAt: now, updatedAt: now };
      repo.pulls.set(number, pull);
      sendJson(res, 201, pullJson(repo, pull));
      return;
    }
    const pullOneMatch = /^\/pulls\/(\d+)$/.exec(rest);
    if (pullOneMatch) {
      const n = Number.parseInt(pullOneMatch[1], 10);
      const pull = repo.pulls.get(n);
      if (!pull) { notFound(res); return; }
      if (method === 'GET') { sendJson(res, 200, pullJson(repo, pull)); return; }
    }
    const pullFilesMatch = /^\/pulls\/(\d+)\/files$/.exec(rest);
    if (pullFilesMatch && method === 'GET') {
      const n = Number.parseInt(pullFilesMatch[1], 10);
      const pull = repo.pulls.get(n);
      if (!pull) { notFound(res); return; }
      const baseCommit = parseCommit(repo.objects.get(pull.baseSha)!.data);
      const headCommit = parseCommit(repo.objects.get(pull.headSha)!.data);
      const changes = diffPaths(repo, baseCommit.tree, headCommit.tree);
      sendJson(res, 200, changes.map((c) => ({ filename: c.path, status: c.status, additions: 1, deletions: 0, changes: 1 })));
      return;
    }
    const mergeMatch = /^\/pulls\/(\d+)\/merge$/.exec(rest);
    if (mergeMatch && method === 'PUT') {
      const n = Number.parseInt(mergeMatch[1], 10);
      const pull = repo.pulls.get(n);
      if (!pull) { notFound(res); return; }
      if (pull.merged) { sendJson(res, 200, { sha: pull.mergeCommitSha, merged: true, message: 'Pull Request already merged' }); return; }
      const currentBase = repo.refs.get(`refs/heads/${pull.base}`);
      if (currentBase !== pull.baseSha) {
        // The base branch moved since the PR was opened: require an up-to-date base, as a
        // conservative (and deterministic) stand-in for real merge-conflict detection.
        sendJson(res, 405, { message: 'Pull Request is not mergeable' });
        return;
      }
      const baseTip = repo.refs.get(`refs/heads/${pull.base}`)!;
      const baseCommit = parseCommit(repo.objects.get(baseTip)!.data);
      const headCommit = parseCommit(repo.objects.get(pull.headSha)!.data);
      void baseCommit;
      const message = `Merge pull request #${n} from ${pull.head}\n\n${pull.title}\n`;
      const commitOid = putObject(repo, 'commit', buildCommit({
        tree: headCommit.tree, parents: [baseTip], message,
        author: `${AUTH_LOGIN} <${AUTH_LOGIN}@example.invalid> 1735689600 +0000`,
        committer: `${AUTH_LOGIN} <${AUTH_LOGIN}@example.invalid> 1735689600 +0000`,
      }));
      repo.refs.set(`refs/heads/${pull.base}`, commitOid);
      pull.merged = true; pull.state = 'closed'; pull.mergedAt = nowIso(); pull.mergeCommitSha = commitOid; pull.updatedAt = nowIso();
      sendJson(res, 200, { sha: commitOid, merged: true, message: 'Pull Request successfully merged' });
      return;
    }
  }

  notFound(res);
}

function walkTree(repo: RepoRecord, treeOid: string, filePath: string): { oid: string; mode: string } | null {
  const segments = filePath.split('/').filter(Boolean);
  let oid = treeOid;
  let mode = '40000';
  for (const seg of segments) {
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === seg);
    if (!entry) return null;
    oid = entry.oid; mode = entry.mode;
  }
  return { oid, mode };
}

function writeFileIntoTree(repo: RepoRecord, treeOid: string, filePath: string, blobOid: string): string {
  const segments = filePath.split('/').filter(Boolean);
  const entries = treeOid ? parseTree(repo.objects.get(treeOid)?.data ?? Buffer.alloc(0)) : [];
  if (segments.length === 1) {
    const rest = entries.filter((e) => e.name !== segments[0]);
    rest.push({ mode: '100644', name: segments[0], oid: blobOid });
    return putObject(repo, 'tree', buildTree(rest));
  }
  const [head, ...tail] = segments;
  const existing = entries.find((e) => e.name === head);
  const subTree = writeFileIntoTree(repo, existing?.mode === '40000' ? existing.oid : '', tail.join('/'), blobOid);
  const rest = entries.filter((e) => e.name !== head);
  rest.push({ mode: '40000', name: head, oid: subTree });
  return putObject(repo, 'tree', buildTree(rest));
}

function deleteFromTree(repo: RepoRecord, treeOid: string, filePath: string): string {
  const segments = filePath.split('/').filter(Boolean);
  const entries = parseTree(repo.objects.get(treeOid)?.data ?? Buffer.alloc(0));
  if (segments.length === 1) {
    const rest = entries.filter((e) => e.name !== segments[0]);
    return putObject(repo, 'tree', buildTree(rest));
  }
  const [head, ...tail] = segments;
  const existing = entries.find((e) => e.name === head);
  if (!existing) return treeOid;
  const subTree = deleteFromTree(repo, existing.oid, tail.join('/'));
  const rest = entries.filter((e) => e.name !== head);
  rest.push({ mode: '40000', name: head, oid: subTree });
  return putObject(repo, 'tree', buildTree(rest));
}

// ======================================================================================
// GraphQL v4 (minimal: enough for introspection + repository/issues/pullRequests/createPullRequest)
// ======================================================================================

function gqlFindRepo(ownerName: string, repoName: string): RepoRecord | undefined {
  return store.get(ownerName, repoName);
}

function gqlIssueNode(repo: RepoRecord, issue: IssueRecord): Record<string, unknown> {
  return { id: `issue:${repo.owner}/${repo.name}#${issue.number}`, number: issue.number, title: issue.title, state: issue.state.toUpperCase(), body: issue.body };
}
function gqlPullNode(repo: RepoRecord, pull: PullRecord): Record<string, unknown> {
  return {
    id: `pr:${repo.owner}/${repo.name}#${pull.number}`, number: pull.number, headRefName: pull.head, baseRefName: pull.base,
    mergeable: 'MERGEABLE', state: pull.merged ? 'MERGED' : pull.state.toUpperCase(), merged: pull.merged,
    files: { nodes: [] },
  };
}
function gqlRepoNode(repo: RepoRecord): Record<string, unknown> {
  return {
    id: `repo:${repo.owner}/${repo.name}`, databaseId: repo.id, name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner }, defaultBranchRef: { name: repo.defaultBranch },
    viewerPermission: 'ADMIN', hasIssuesEnabled: true,
  };
}

const INTROSPECTION_TYPES: Record<string, { kind: string; fields?: string[]; enumValues?: string[] }> = {
  Issue: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body'] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'] },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'] },
};

function introspectType(name: string): Record<string, unknown> | null {
  const t = INTROSPECTION_TYPES[name];
  if (!t) return null;
  if (t.kind === 'ENUM') return { name, kind: 'ENUM', enumValues: t.enumValues!.map((v) => ({ name: v })) };
  return { name, kind: 'OBJECT', fields: t.fields!.map((f) => ({ name: f })) };
}

/** Extremely small GraphQL-ish executor: enough for the fixed documents gh / github-mcp-server send. */
function execOneGraphQL(query: string, variables: Record<string, unknown>): { data?: unknown; errors?: Array<{ message: string }> } {
  const isMutation = /^\s*mutation\b/.test(query);
  const typeMatches = [...query.matchAll(/__type\s*\(\s*name:\s*"([^"]+)"\s*\)/g)];
  if (typeMatches.length) {
    const name = typeMatches[0][1];
    const result = introspectType(name);
    return { data: { __type: result } };
  }
  if (!isMutation) {
    const repoMatch = /repository\s*\(\s*owner:\s*\$?(\w+)|owner:\s*"([^"]*)"/i.exec(query);
    const ownerVar = (variables.owner as string) ?? repoMatch?.[2];
    const nameVar = (variables.name as string) ?? /name:\s*"([^"]*)"/.exec(query)?.[1];
    if (/repository\s*\(/.test(query)) {
      const repo = ownerVar && nameVar ? gqlFindRepo(ownerVar, nameVar) : undefined;
      if (!repo) return { data: { repository: null } };
      const node = gqlRepoNode(repo) as Record<string, unknown>;
      if (/issue\s*\(/.test(query) && typeof variables.number === 'number') {
        const issue = repo.issues.get(variables.number as number);
        node.issue = issue ? gqlIssueNode(repo, issue) : null;
      }
      if (/pullRequest\s*\(/.test(query) && typeof variables.number === 'number') {
        const pull = repo.pulls.get(variables.number as number);
        node.pullRequest = pull ? gqlPullNode(repo, pull) : null;
      }
      if (/issues\s*\(/.test(query)) {
        const statesMatch = /states:\s*\[([A-Z, ]+)\]/.exec(query);
        const wantOpen = statesMatch ? statesMatch[1].includes('OPEN') && !statesMatch[1].includes('CLOSED') : null;
        let list = [...repo.issues.values()].filter((i) => !i.isPull);
        if (wantOpen === true) list = list.filter((i) => i.state === 'open');
        list.sort((a, b) => b.number - a.number);
        node.issues = { nodes: list.map((i) => gqlIssueNode(repo, i)), totalCount: list.length };
      }
      if (/pullRequests\s*\(/.test(query)) {
        const list = [...repo.pulls.values()].sort((a, b) => b.number - a.number);
        node.pullRequests = { nodes: list.map((p) => gqlPullNode(repo, p)), totalCount: list.length };
      }
      return { data: { repository: node } };
    }
    if (/\bviewer\s*\{/.test(query)) return { data: { viewer: { login: AUTH_LOGIN } } };
    const fieldMatch = /\{\s*(\w+)/.exec(query.replace(/^\s*query[^{]*/, ''));
    if (fieldMatch) return { errors: [{ message: `Field '${fieldMatch[1]}' doesn't exist on type 'Query'` }] };
    return { errors: [{ message: 'unrecognized query' }] };
  }
  // mutation
  if (/createPullRequest/.test(query)) {
    const input = (variables.input as Record<string, unknown>) ?? variables;
    const repoId = String(input.repositoryId ?? '');
    const m = /^repo:([^/]+)\/(.+)$/.exec(repoId);
    const repo = m ? gqlFindRepo(m[1], m[2]) : undefined;
    if (!repo) return { errors: [{ message: 'Could not resolve to a Repository' }] };
    const head = String(input.headRefName ?? '');
    const base = String(input.baseRefName ?? repo.defaultBranch);
    const headSha = repo.refs.get(`refs/heads/${head}`);
    const baseSha = repo.refs.get(`refs/heads/${base}`);
    if (!headSha || !baseSha) return { errors: [{ message: 'head or base branch not found' }] };
    const number = nextIssueNumber(repo);
    const now = nowIso();
    const pull: PullRecord = {
      number, title: String(input.title ?? ''), body: String(input.body ?? ''), state: 'open', merged: false,
      mergedAt: null, mergeCommitSha: null, head, base, headSha, baseSha, createdAt: now, updatedAt: now,
    };
    repo.pulls.set(number, pull);
    return { data: { createPullRequest: { pullRequest: gqlPullNode(repo, pull) } } };
  }
  return { errors: [{ message: 'unrecognized mutation' }] };
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!authed(req)) { unauthorized(res); return; }
  const body = await readBody(req);
  let json: Record<string, unknown> | Array<Record<string, unknown>>;
  try { json = JSON.parse(body.toString('utf8') || '{}'); } catch { badRequest(res); return; }
  const docs = Array.isArray(json) ? json : [json];
  const results = docs.map((doc) => execOneGraphQL(String(doc.query ?? ''), (doc.variables as Record<string, unknown>) ?? {}));
  sendJson(res, 200, Array.isArray(json) ? results : results[0]);
}

// ======================================================================================
// MCP (JSON-RPC 2.0 over streamable HTTP)
// ======================================================================================

const MCP_TOOLS: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> = [
  { name: 'create_repo', description: 'Create a repository owned by the authenticated user', inputSchema: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Open a pull request', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'number' } }, required: ['owner', 'repo', 'pull_number'] } },
];

function findTool(name: string): string | null {
  const lower = name.toLowerCase();
  for (const t of MCP_TOOLS) if (lower === t.name || lower.endsWith(`__${t.name}`) || lower.endsWith(`_${t.name}`)) return t.name;
  return null;
}

function mcpCallTool(name: string, args: Record<string, unknown>): { isError?: boolean; content: Array<{ type: 'text'; text: string }> } {
  const owner = String(args.owner ?? AUTH_LOGIN);
  const repoName = String(args.repo ?? args.full_name ?? '');
  try {
    if (name === 'create_repo') {
      const rname = String(args.name ?? '');
      if (!rname) return { isError: true, content: [{ type: 'text', text: 'name is required' }] };
      const repo = store.get(AUTH_LOGIN, rname) ?? store.create(AUTH_LOGIN, rname, {});
      return { content: [{ type: 'text', text: JSON.stringify(repoJson(repo)) }] };
    }
    if (name === 'get_repo') {
      const repo = store.get(owner, repoName);
      if (!repo) return { isError: true, content: [{ type: 'text', text: 'not found' }] };
      return { content: [{ type: 'text', text: JSON.stringify(repoJson(repo)) }] };
    }
    if (name === 'create_issue') {
      const repo = store.get(owner, repoName);
      if (!repo) return { isError: true, content: [{ type: 'text', text: 'not found' }] };
      const number = nextIssueNumber(repo);
      const now = nowIso();
      const issue: IssueRecord = { number, title: String(args.title ?? ''), body: String(args.body ?? ''), state: 'open', labels: [], createdAt: now, updatedAt: now, closedAt: null, comments: [], isPull: false };
      repo.issues.set(number, issue);
      return { content: [{ type: 'text', text: JSON.stringify(issueJson(repo, issue)) }] };
    }
    if (name === 'list_issues') {
      const repo = store.get(owner, repoName);
      if (!repo) return { isError: true, content: [{ type: 'text', text: 'not found' }] };
      const state = args.state ? String(args.state) : 'open';
      let list = [...repo.issues.values()].filter((i) => !i.isPull);
      if (state !== 'all') list = list.filter((i) => i.state === state);
      return { content: [{ type: 'text', text: JSON.stringify(list.map((i) => issueJson(repo, i))) }] };
    }
    if (name === 'create_pull_request') {
      const repo = store.get(owner, repoName);
      if (!repo) return { isError: true, content: [{ type: 'text', text: 'not found' }] };
      const head = String(args.head ?? '');
      const base = String(args.base ?? repo.defaultBranch);
      const headSha = repo.refs.get(`refs/heads/${head}`);
      const baseSha = repo.refs.get(`refs/heads/${base}`);
      if (!headSha || !baseSha) return { isError: true, content: [{ type: 'text', text: 'head or base not found' }] };
      const number = nextIssueNumber(repo);
      const now = nowIso();
      const pull: PullRecord = { number, title: String(args.title ?? ''), body: String(args.body ?? ''), state: 'open', merged: false, mergedAt: null, mergeCommitSha: null, head, base, headSha, baseSha, createdAt: now, updatedAt: now };
      repo.pulls.set(number, pull);
      return { content: [{ type: 'text', text: JSON.stringify(pullJson(repo, pull)) }] };
    }
    if (name === 'merge_pull_request') {
      const repo = store.get(owner, repoName);
      if (!repo) return { isError: true, content: [{ type: 'text', text: 'not found' }] };
      const n = Number(args.pull_number ?? args.pullNumber ?? NaN);
      const pull = repo.pulls.get(n);
      if (!pull) return { isError: true, content: [{ type: 'text', text: 'not found' }] };
      const baseTip = repo.refs.get(`refs/heads/${pull.base}`)!;
      const headCommit = parseCommit(repo.objects.get(pull.headSha)!.data);
      const commitOid = putObject(repo, 'commit', buildCommit({
        tree: headCommit.tree, parents: [baseTip], message: `Merge pull request #${n} from ${pull.head}\n`,
        author: `${AUTH_LOGIN} <${AUTH_LOGIN}@example.invalid> 1735689600 +0000`,
        committer: `${AUTH_LOGIN} <${AUTH_LOGIN}@example.invalid> 1735689600 +0000`,
      }));
      repo.refs.set(`refs/heads/${pull.base}`, commitOid);
      pull.merged = true; pull.state = 'closed'; pull.mergedAt = nowIso(); pull.mergeCommitSha = commitOid;
      return { content: [{ type: 'text', text: JSON.stringify({ merged: true, sha: commitOid }) }] };
    }
  } catch (err) {
    return { isError: true, content: [{ type: 'text', text: err instanceof Error ? err.message : String(err) }] };
  }
  return { isError: true, content: [{ type: 'text', text: 'unknown tool' }] };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!authed(req)) { sendJson(res, 401, { message: 'Requires authentication' }); return; }
  const body = await readBody(req);
  let json: Record<string, unknown>;
  try { json = JSON.parse(body.toString('utf8') || '{}'); } catch {
    res.writeHead(400, { 'content-type': JSON_TYPE });
    res.end(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })}\n`);
    return;
  }
  const id = (json as { id?: unknown }).id ?? null;
  const methodName = String((json as { method?: unknown }).method ?? '');
  const params = ((json as { params?: unknown }).params ?? {}) as Record<string, unknown>;
  const reply = (result: unknown): void => { sendJson(res, 200, { jsonrpc: '2.0', id, result }); };
  const replyError = (code: number, message: string): void => { sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } }); };

  if (methodName === 'initialize') {
    reply({ protocolVersion: '2026-07-28', capabilities: { tools: {} }, serverInfo: { name: 'makefun-forge', version: '1.0.0' } });
    return;
  }
  if (methodName === 'notifications/initialized') { res.writeHead(200, { 'content-type': JSON_TYPE }); res.end(); return; }
  if (methodName === 'server/discover' || methodName === 'discover') {
    reply({ supportedVersions: ['2026-07-28', '2025-11-25'] });
    return;
  }
  if (methodName === 'tools/list') { reply({ tools: MCP_TOOLS }); return; }
  if (methodName === 'tools/call') {
    const toolName = String(params.name ?? '');
    const resolved = findTool(toolName);
    if (!resolved) { replyError(-32601, `unknown tool ${toolName}`); return; }
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const required: Record<string, string[]> = {
      create_repo: ['name'], get_repo: ['owner', 'repo'], create_issue: ['owner', 'repo', 'title'],
      list_issues: ['owner', 'repo'], create_pull_request: ['owner', 'repo', 'title', 'head', 'base'], merge_pull_request: ['owner', 'repo', 'pull_number'],
    };
    for (const field of required[resolved] ?? []) {
      if (args[field] === undefined) { reply({ isError: true, content: [{ type: 'text', text: `missing argument ${field}` }] }); return; }
    }
    reply(mcpCallTool(resolved, args));
    return;
  }
  replyError(-32601, `unknown method ${methodName}`);
}

// ======================================================================================
// top-level router
// ======================================================================================

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    let url: URL;
    try { url = new URL(req.url ?? '/', 'http://entry'); } catch { notFound(res); return; }
    const path = url.pathname;
    const method = req.method ?? 'GET';

    if (method === 'GET' && path === '/healthz') { sendJson(res, 200, { ok: true }); return; }

    const gitMatch = GIT_PATH_RE.exec(path);
    if (gitMatch) {
      const [, owner, repoName, tail] = gitMatch;
      const suffix = tail ?? '';
      if (suffix === '/info/refs' && method === 'GET') { handleInfoRefs(req, res, owner, repoName, url.searchParams); return; }
      if (suffix === '/git-upload-pack' && method === 'POST') {
        const repo = store.get(owner, repoName);
        if (!repo) { notFound(res); return; }
        handleUploadPack(req, res, repo).catch(() => { try { res.destroy(); } catch { /* ignore */ } });
        return;
      }
      if (suffix === '/git-receive-pack' && method === 'POST') {
        const repo = store.get(owner, repoName);
        if (!repo) { notFound(res); return; }
        handleReceivePack(req, res, repo).catch(() => { try { res.destroy(); } catch { /* ignore */ } });
        return;
      }
      notFound(res);
      return;
    }

    if (path.startsWith('/api/v3')) {
      handleRest(req, res, path, url.searchParams).catch((err) => {
        try { sendJson(res, 400, { message: err instanceof Error ? err.message : String(err) }); } catch { /* already sent */ }
      });
      return;
    }
    if (path === '/api/graphql' && method === 'POST') {
      handleGraphQL(req, res).catch(() => { try { badRequest(res); } catch { /* ignore */ } });
      return;
    }
    if (path === '/mcp' && method === 'POST') {
      handleMcp(req, res).catch(() => { try { badRequest(res); } catch { /* ignore */ } });
      return;
    }

    notFound(res);
  });
}

void applyDelta; void buildTagShim; void pktDelim;
