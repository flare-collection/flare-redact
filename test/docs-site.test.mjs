import { test } from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const docsDir = fileURLToPath(new URL('../docs/', import.meta.url));
const siteRoot = 'https://flare-collection.github.io/flare-redact/';
const pages = [
  'index.html',
  'guides/index.html',
  'guides/pii-redaction-javascript/index.html',
  'guides/redact-secrets-nodejs-logs/index.html',
  'guides/llm-prompt-redaction/index.html',
  'guides/mcp-tool-redaction/index.html',
];

const readPage = async (relativePath) => ({
  relativePath,
  html: await readFile(path.join(docsDir, relativePath), 'utf8'),
});

const captureOne = (html, pattern, label) => {
  const matches = [...html.matchAll(pattern)];
  assert.equal(matches.length, 1, `${label} must appear exactly once`);
  return matches[0][1];
};

test('every search page has unique metadata, one h1, and valid structured data', async () => {
  const seenTitles = new Set();
  const seenCanonicals = new Set();

  for (const { relativePath, html } of await Promise.all(pages.map(readPage))) {
    assert.match(html, /<html lang="en">/, `${relativePath} language`);
    const title = captureOne(html, /<title>([^<]+)<\/title>/g, `${relativePath} title`);
    const canonical = captureOne(
      html,
      /<link rel="canonical" href="([^"]+)">/g,
      `${relativePath} canonical`,
    );
    captureOne(
      html,
      /<meta name="description" content="([^"]+)">/g,
      `${relativePath} description`,
    );
    captureOne(html, /<h1(?:\s[^>]*)?>([\s\S]*?)<\/h1>/g, `${relativePath} h1`);

    assert.ok(!seenTitles.has(title), `${relativePath} title must be unique`);
    assert.ok(!seenCanonicals.has(canonical), `${relativePath} canonical must be unique`);
    seenTitles.add(title);
    seenCanonicals.add(canonical);

    const structuredData = [...html.matchAll(
      /<script type="application\/ld\+json">([\s\S]*?)<\/script>/g,
    )];
    assert.ok(structuredData.length > 0, `${relativePath} structured data`);
    for (const [, json] of structuredData) assert.doesNotThrow(() => JSON.parse(json));
  }
});

test('every local page link resolves to a published docs file', async () => {
  for (const { relativePath, html } of await Promise.all(pages.map(readPage))) {
    const canonical = captureOne(
      html,
      /<link rel="canonical" href="([^"]+)">/g,
      `${relativePath} canonical`,
    );
    const links = [...html.matchAll(/href="([^"]+)"/g)].map((match) => match[1]);

    for (const href of links) {
      if (href.startsWith('#') || href.startsWith('mailto:')) continue;
      const resolved = new URL(href, canonical);
      if (!resolved.href.startsWith(siteRoot)) continue;

      let target = decodeURIComponent(resolved.pathname.slice('/flare-redact/'.length));
      if (target === '' || target.endsWith('/')) target += 'index.html';
      await assert.doesNotReject(
        access(path.join(docsDir, target)),
        `${relativePath} has broken local link ${href}`,
      );
    }
  }
});

test('sitemap contains each canonical search page exactly once', async () => {
  const sitemap = await readFile(path.join(docsDir, 'sitemap.xml'), 'utf8');
  const locations = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
  assert.equal(new Set(locations).size, locations.length, 'sitemap URLs must be unique');

  for (const { html } of await Promise.all(pages.map(readPage))) {
    const canonical = captureOne(
      html,
      /<link rel="canonical" href="([^"]+)">/g,
      'page canonical',
    );
    assert.ok(locations.includes(canonical), `${canonical} must be listed in sitemap`);
  }
});

test('the playground identifies the current release', async () => {
  const html = await readFile(path.join(docsDir, 'index.html'), 'utf8');
  assert.match(html, /v1\.4\.1 · runs entirely in your browser/);
  assert.doesNotMatch(html, /v1\.2\.0/);
});
