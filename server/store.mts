import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { sign, equal } from './security.mts';
import type { Records, RecordKind, AuditEntry, Integrity } from './models.mts';
export class Store {
  key: string;
  db: DatabaseSync;
  constructor(path: string, key: string) {
    this.key = key;
    this.db = new DatabaseSync(path);
    this.db.exec(
      'PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; CREATE TABLE IF NOT EXISTS records(kind TEXT NOT NULL,id TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(kind,id)); CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,data TEXT NOT NULL,hash TEXT NOT NULL);',
    );
  }
  list<K extends RecordKind>(kind: K): Records[K][] {
    return this.db
      .prepare('SELECT data FROM records WHERE kind=? ORDER BY rowid DESC')
      .all(kind)
      .map((r) => JSON.parse(String(r.data)) as Records[K]);
  }
  get<K extends RecordKind>(kind: K, id: string): Records[K] | null {
    const row = this.db.prepare('SELECT data FROM records WHERE kind=? AND id=?').get(kind, id);
    return row ? (JSON.parse(String(row.data)) as Records[K]) : null;
  }
  put<K extends RecordKind>(kind: K, value: Records[K]): Records[K] {
    this.db
      .prepare(
        'INSERT INTO records(kind,id,data) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data',
      )
      .run(kind, value.id, JSON.stringify(value));
    return value;
  }
  create<K extends RecordKind>(kind: K, value: Omit<Records[K], 'id' | 'createdAt'>): Records[K] {
    return this.put(kind, {
      ...value,
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
    } as Records[K]);
  }
  transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  audit(actor: string, action: string, detail: string) {
    const previous =
      this.db.prepare('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').get()?.hash || 'genesis';
    const data = { time: new Date().toISOString(), actor, action, detail, previous };
    const hash = sign(data, this.key);
    this.db.prepare('INSERT INTO audit(data,hash) VALUES(?,?)').run(JSON.stringify(data), hash);
    return hash;
  }
  auditRows(): AuditEntry[] {
    return this.db
      .prepare('SELECT seq,data,hash FROM audit ORDER BY seq DESC LIMIT 250')
      .all()
      .map(
        (row) =>
          ({
            ...JSON.parse(String(row.data)),
            seq: Number(row.seq),
            hash: String(row.hash),
          }) as AuditEntry,
      );
  }
  integrity(): Integrity {
    let previous = 'genesis',
      count = 0;
    for (const row of this.db.prepare('SELECT data,hash FROM audit ORDER BY seq').iterate()) {
      const data = JSON.parse(String(row.data)) as AuditEntry;
      if (data.previous !== previous || !equal(sign(data, this.key), row.hash))
        return { valid: false, count };
      previous = String(row.hash);
      count++;
    }
    return { valid: true, count, head: previous };
  }
  close() {
    this.db.close();
  }
}
