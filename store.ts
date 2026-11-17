// In-memory store for the forge: repositories, refs, git objects, issues and pull requests.
// Everything lives in process memory only (no filesystem, no clock-derived ids), so two runs on
// the same seed behave identically as long as requests arrive in the same order.

import type { GitObject, GitObjectType } from './git.ts';
import { hashObject, parseCommit, parseTree, isObjectId } from './git.ts';

export interface RepoRecord {
  id: number;
  owner: string;
  name: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  createdAt: string;
  refs: Map<string, string>; // refname -> oid
  objects: Map<string, GitObject>;
  nextNumber: number; // shared issue/PR numbering
  issues: Map<number, IssueRecord>;
  pulls: Map<number, PullRecord>;
  labels: Map<string, { name: string; color: string }>;
}

export interface CommentRecord { id: number; body: string; createdAt: string; }

export interface IssueRecord {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  comments: CommentRecord[];
  isPull: boolean;
}

export interface PullRecord {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  head: string; // branch name
  base: string; // branch name
  headSha: string;
  baseSha: string;
  createdAt: string;
  updatedAt: string;
}

let nextRepoId = 9000;
let nextCommentId = 1;

export class Store {
  repos = new Map<string, RepoRecord>(); // `${owner}/${name}` -> record
  owner: string;

  constructor(owner: string) { this.owner = owner; }

  key(owner: string, name: string): string { return `${owner}/${name}`; }

  get(owner: string, name: string): RepoRecord | undefined { return this.repos.get(this.key(owner, name)); }

  create(owner: string, name: string, opts: { description?: string; private?: boolean }): RepoRecord {
    const now = ISO_EPOCH;
    const record: RepoRecord = {
      id: nextRepoId++,
      owner,
      name,
      description: opts.description ?? '',
      private: opts.private ?? false,
      defaultBranch: 'main',
      createdAt: now,
      refs: new Map(),
      objects: new Map(),
      nextNumber: 1,
      issues: new Map(),
      pulls: new Map(),
      labels: new Map(),
    };
    this.repos.set(this.key(owner, name), record);
    return record;
  }

  delete(owner: string, name: string): void { this.repos.delete(this.key(owner, name)); }

  list(owner: string): RepoRecord[] {
    return [...this.repos.values()].filter((r) => r.owner === owner);
  }
}

// A fixed, deterministic timestamp: never Date.now() inside the forge's own logic, so two runs
// against the same instance produce identical issue/commit timestamps where the forge invents one.
export const ISO_EPOCH = '2025-01-01T00:00:00Z';

export function putObject(repo: RepoRecord, type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

/** reachable(roots) bounded: stops expanding a commit's parents once it is in `stop`. */
export function boundedReachable(repo: RepoRecord, roots: Iterable<string>, stop: ReadonlySet<string> = new Set()): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...roots].filter(isObjectId);
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      if (isObjectId(c.tree)) queue.push(c.tree);
      if (!stop.has(oid)) for (const p of c.parents) queue.push(p);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) if (e.mode !== '160000') queue.push(e.oid);
    } else if (obj.type === 'tag') {
      const t = obj.data.toString('utf8');
      const m = /^object ([0-9a-f]{40})/.exec(t);
      if (m) queue.push(m[1]);
    }
  }
  return seen;
}

export function reachable(repo: RepoRecord, roots: Iterable<string>): Set<string> {
  return boundedReachable(repo, roots, new Set());
}

/** Depth-limited BFS over commits only (trees/blobs are added afterwards, unconditionally). */
export function depthClosure(repo: RepoRecord, wants: string[], depth: number): { commits: Set<string>; boundary: Set<string> } {
  const level = new Map<string, number>();
  const queue: Array<[string, number]> = wants.map((w) => [w, 0]);
  while (queue.length) {
    const [oid, lvl] = queue.shift()!;
    const existing = level.get(oid);
    if (existing !== undefined && existing <= lvl) continue;
    level.set(oid, lvl);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    if (lvl < depth - 1) {
      const c = parseCommit(obj.data);
      for (const p of c.parents) queue.push([p, lvl + 1]);
    }
  }
  const commits = new Set(level.keys());
  const boundary = new Set<string>();
  for (const oid of commits) {
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const c = parseCommit(obj.data);
    if (c.parents.some((p) => !commits.has(p)) && c.parents.length > 0) boundary.add(oid);
  }
  return { commits, boundary };
}

export function treeAndBlobsOf(repo: RepoRecord, commitOids: Iterable<string>): Set<string> {
  const out = new Set<string>();
  for (const oid of commitOids) {
    out.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const c = parseCommit(obj.data);
    for (const sub of boundedReachable(repo, [c.tree], new Set())) out.add(sub);
  }
  return out;
}
