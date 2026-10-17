// 테스트 전용 인메모리 Supabase 대역. 실제 DB가 아니며 네트워크를 쓰지 않는다.
// 이 저장소의 코드가 쓰는 필터(eq, is, not(is), gt)와 select/insert/update/delete만 흉내 낸다.
import { randomUUID } from 'node:crypto';

const UNIQUE = {
  device_credentials: ['credential_id'],
  device_challenges: ['challenge'],
  device_sessions: ['token_hash'],
  learning_notes: ['id'],
};

export class FakeDb {
  constructor() {
    this.tables = {
      device_credentials: [],
      device_challenges: [],
      device_sessions: [],
      learning_notes: [],
    };
    this.calls = [];
    // 'table:op' 형태로 넣으면 해당 호출이 DB 오류로 실패한다. 예: 'device_sessions:select'
    this.failures = new Set();
  }

  client() {
    return { from: table => new Query(this, table) };
  }

  rows(table) {
    return this.tables[table];
  }

  callsTo(table) {
    return this.calls.filter(call => call.table === table);
  }
}

class Query {
  constructor(db, table) {
    this.db = db;
    this.table = table;
    this.op = 'select';
    this.filters = [];
    this.values = null;
    this.returning = false;
    this.single = false;
  }

  select() {
    if (this.op === 'select') this.op = 'select';
    this.returning = true;
    return this;
  }

  insert(values) {
    this.op = 'insert';
    this.values = values;
    return this;
  }

  update(values) {
    this.op = 'update';
    this.values = values;
    return this;
  }

  delete() {
    this.op = 'delete';
    return this;
  }

  eq(column, value) {
    this.filters.push(row => (row[column] ?? null) === value);
    return this;
  }

  is(column, value) {
    this.filters.push(row => (row[column] ?? null) === value);
    return this;
  }

  not(column, operator, value) {
    if (operator !== 'is') throw new Error(`fake: unsupported not(${operator})`);
    this.filters.push(row => (row[column] ?? null) !== value);
    return this;
  }

  gt(column, value) {
    this.filters.push(row => Date.parse(row[column]) > Date.parse(value));
    return this;
  }

  order() {
    return this;
  }

  maybeSingle() {
    this.single = true;
    return this;
  }

  then(resolve, reject) {
    return Promise.resolve().then(() => this.execute()).then(resolve, reject);
  }

  execute() {
    const { db, table } = this;
    db.calls.push({ table, op: this.op });
    if (db.failures.has(`${table}:${this.op}`)) {
      return { data: null, error: { code: 'XX000', message: 'injected failure' } };
    }

    const rows = db.tables[table];
    const matches = () => rows.filter(row => this.filters.every(filter => filter(row)));
    const shape = list => (this.single ? (list[0] ?? null) : list);

    if (this.op === 'select') {
      return { data: shape(matches()), error: null };
    }

    if (this.op === 'insert') {
      const incoming = Array.isArray(this.values) ? this.values : [this.values];
      for (const value of incoming) {
        for (const column of UNIQUE[table] ?? []) {
          if (value[column] !== undefined && rows.some(row => row[column] === value[column])) {
            return { data: null, error: { code: '23505', message: 'duplicate' } };
          }
        }
      }
      for (const value of incoming) {
        rows.push({
          id: randomUUID(),
          created_at: new Date().toISOString(),
          consumed_at: null,
          revoked_at: null,
          approved_by: null,
          approved_at: null,
          ...value,
        });
      }
      return { data: null, error: null };
    }

    if (this.op === 'update') {
      const hit = matches();
      for (const row of hit) Object.assign(row, this.values);
      return { data: this.returning ? shape(hit.map(row => ({ ...row }))) : null, error: null };
    }

    const hit = matches();
    db.tables[table] = rows.filter(row => !hit.includes(row));
    return { data: this.returning ? shape(hit) : null, error: null };
  }
}
