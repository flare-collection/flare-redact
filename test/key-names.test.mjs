import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, isSensitiveKeyName } from '../dist/index.js';

const sensitive = [
  'password', 'Api_Secret', 'api_secret', 'apiSecret', 'db_password', 'DbPassword',
  'accessToken', 'Access_Token', 'aws_secret_access_key', 'GITHUB_TOKEN', 'OPENAI_API_KEY',
  'STRIPE_SECRET_KEY', 'SLACK_BOT_TOKEN', 'SENTRY_DSN', 'JWT_SECRET', 'SMTP_PASS', 'db_pwd',
  'x-api-key', 'set-cookie', 'proxy-authorization', 'x-auth-token', 'otp', 'user_pin',
  'card_cvv', 'privateKey', 'encryptionKey', 'connectionString', 'seed_phrase', 'mnemonic',
  'idToken', 'sessionId', 'creditCardNumber', 'basic_auth', 'page_access_token', 'ŞİFRE', 'APİ_KEY',
];

const readable = [
  'author', 'authority', 'monkey', 'keyboard', 'publicKey', 'tokenizer', 'secretary', 'passport',
  'compass', 'bypass', 'oauth', 'max_tokens', 'input_tokens', 'nextPageToken', 'next_token',
  'continuationToken', 'pageToken', 'secret_name', 'token_type', 'AccessKeyId', 'password_min_length',
  'SSH_AUTH_SOCK', 'username', 'key', 'session', 'spin', 'apiKeyId',
];

test('key names: compound and camel-case credential names are sensitive', () => {
  for (const key of sensitive) assert.ok(isSensitiveKeyName(key), key);
});

test('key names: look-alikes and pagination cursors stay readable', () => {
  for (const key of readable) assert.ok(!isSensitiveKeyName(key), key);
});

test('key names: a process.env dump keeps config and hides credentials', () => {
  const env = {
    NODE_ENV: 'production',
    HOME: '/home/ada',
    DATABASE_PASSWORD: 'pg-pass-1',
    GITHUB_TOKEN: 'gh-1',
    TOKENIZERS_PARALLELISM: 'false',
  };
  assert.deepEqual(redact(env), {
    NODE_ENV: 'production',
    HOME: '/home/ada',
    DATABASE_PASSWORD: '***',
    GITHUB_TOKEN: '***',
    TOKENIZERS_PARALLELISM: 'false',
  });
});
