// Query logs: a bound parameter has no shape a detector can see, so each one
// is matched to its column and masked by name.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  createQueryRedactor,
  drizzleLogger,
  knexQueryLogger,
  prismaQueryLogger,
  redactQuery,
  sequelizeLogging,
  typeormLogger,
} from '../dist/db.js';

const PW = 'hunter2hunter2';
const KEY = 'k-7c1e0f2a9b';

test('positional parameters are masked by the column they bind to', () => {
  assert.deepEqual(
    redactQuery('INSERT INTO "users" ("email", "password", "name") VALUES ($1, $2, $3)', ['ada@example.com', PW, 'Ada']),
    { sql: 'INSERT INTO "users" ("email", "password", "name") VALUES ($1, $2, $3)', params: ['a***@***', '***', 'Ada'] },
  );
  assert.deepEqual(redactQuery('UPDATE users SET api_key = ? WHERE id = ?', [KEY, 7]).params, ['***', 7]);
  assert.deepEqual(
    redactQuery('SELECT * FROM s WHERE token IN ($1, $2) AND user_id = $3', ['abc123def', 'xyz789', 42]).params,
    ['***', '***', 42],
  );
  assert.deepEqual(
    redactQuery('SELECT * FROM `main`.`User` WHERE `main`.`User`.`password` = ? LIMIT ?', [PW, 1]).params,
    ['***', 1],
  );
  assert.deepEqual(redactQuery('select $1::text as x', ['plain']).params, ['plain']);
});

test('named parameters and literals', () => {
  assert.deepEqual(
    redactQuery('SELECT * FROM u WHERE u.secret_hash = :pw AND name = :n AND password = :p2', { pw: 'x', n: 'Ada', p2: PW }).params,
    { pw: 'x', n: 'Ada', p2: '***' },
  );
  const redactor = createQueryRedactor();
  assert.equal(
    redactor.sql("INSERT INTO users (email, password) VALUES ('ada@example.com', 'hunter2hunter2'), ('bob@example.com', 'p''ss')"),
    "INSERT INTO users (email, password) VALUES ('a***@***', '***'), ('b***@***', '***')",
  );
  assert.equal(redactor.sql("SELECT 'it''s fine' -- ada@example.com"), "SELECT 'it''s fine' -- a***@***");
  assert.equal(redactor.sql('SELECT 1'), 'SELECT 1');
});

test('ORM adapters log the redacted query in their own format', () => {
  const lines = [];
  const log = (...args) => lines.push(args);

  prismaQueryLogger(log)({ query: 'UPDATE `User` SET `api_key` = ? WHERE `email` = ?', params: JSON.stringify([KEY, 'ada@example.com']), duration: 1, target: 'x' });
  assert.deepEqual(lines.pop()[0], { query: 'UPDATE `User` SET `api_key` = ? WHERE `email` = ?', params: '["***","a***@***"]', duration: 1, target: 'x' });

  drizzleLogger({}, log).logQuery('update "users" set "api_key" = $1', [KEY]);
  assert.deepEqual(lines.pop(), ['Query: update "users" set "api_key" = $1 -- params: ["***"]']);

  knexQueryLogger(log)({ method: 'insert', sql: 'insert into `users` (`email`, `password`) values (?, ?)', bindings: ['ada@example.com', PW] });
  assert.deepEqual(lines.pop()[0].bindings, ['a***@***', '***']);

  const inner = { logQuery: (q, p) => lines.push([q, p]) };
  typeormLogger(inner).logQuery('INSERT INTO "u"("id", "password") VALUES (NULL, ?)', [PW]);
  assert.deepEqual(lines.pop(), ['INSERT INTO "u"("id", "password") VALUES (NULL, ?)', ['***']]);
});

test('Sequelize lines, with and without logQueryParameters', () => {
  const lines = [];
  const logging = sequelizeLogging((...args) => lines.push(args));
  logging("Executing (default): SELECT * FROM `users` WHERE `password` = 'hunter2hunter2' LIMIT 1;");
  assert.equal(lines.pop()[0], "Executing (default): SELECT * FROM `users` WHERE `password` = '***' LIMIT 1;");
  logging(`Executing (default): INSERT INTO \`users\` (\`id\`,\`email\`,\`password\`) VALUES (NULL,$1,$2); {"$1":"ada@example.com","$2":"${PW}"}`, 12);
  assert.deepEqual(lines.pop(), ['Executing (default): INSERT INTO `users` (`id`,`email`,`password`) VALUES (NULL,$1,$2); {"$1":"a***@***","$2":"***"}', 12]);
  logging(`Executing (default): UPDATE \`users\` SET \`api_key\`=? WHERE \`id\` = ?; "${KEY}", 7`);
  assert.equal(lines.pop()[0], 'Executing (default): UPDATE `users` SET `api_key`=? WHERE `id` = ?; "***", 7');
});
