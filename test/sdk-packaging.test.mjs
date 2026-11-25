// The Python, Rust, Java and .NET engines are published to PyPI, crates.io,
// Maven Central and NuGet by the same push that publishes npm. The publish jobs trust the version written in each
// manifest, so a manifest left behind on a release would ship the wrong number,
// or ship nothing. These checks keep every manifest on one version and keep the
// licence text inside each package that leaves the repository.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const { version } = JSON.parse(read('package.json'));

function tomlVersion(text, section) {
  const start = text.indexOf(`[${section}]`);
  assert.notEqual(start, -1, `[${section}] section`);
  const match = text.slice(start).match(/^version\s*=\s*"([^"]+)"/m);
  assert.ok(match, `version in [${section}]`);
  return match[1];
}

test('every engine carries the npm package version', () => {
  assert.equal(tomlVersion(read('sdk/python/pyproject.toml'), 'project'), version, 'sdk/python/pyproject.toml');
  assert.equal(
    read('sdk/python/src/flare_redact/__init__.py').match(/^__version__ = "([^"]+)"/m)?.[1],
    version,
    'flare_redact.__version__',
  );
  assert.equal(tomlVersion(read('sdk/rust/Cargo.toml'), 'package'), version, 'sdk/rust/Cargo.toml');
  const lock = read('sdk/rust/Cargo.lock');
  assert.match(lock, new RegExp(`name = "flare-redact"\\r?\\nversion = "${version.replace(/\./g, '\\.')}"`), 'sdk/rust/Cargo.lock');
});

test('the Java and .NET packages carry the npm package version', () => {
  // The parent pom's own version, then each module's <parent> reference to it.
  for (const pom of ['sdk/java/pom.xml', 'sdk/java/core/pom.xml', 'sdk/java/logback/pom.xml', 'sdk/java/log4j2/pom.xml']) {
    const text = read(pom).replace(/<dependencies>[\s\S]*?<\/dependencies>/g, '');
    const own = text.match(/<artifactId>flare-redact(?:-parent)?<\/artifactId>\s*<version>([^<]+)<\/version>/);
    assert.equal(own?.[1], version, pom);
  }
  assert.equal(
    read('sdk/java/core/src/main/java/io/github/flarecollection/redact/FlareRedact.java').match(/VERSION = "([^"]+)"/)?.[1],
    version,
    'FlareRedact.VERSION',
  );
  assert.equal(read('sdk/dotnet/Directory.Build.props').match(/<Version>([^<]+)<\/Version>/)?.[1], version, 'Directory.Build.props');
  assert.equal(
    read('sdk/dotnet/src/FlareRedact/Redactor.cs').match(/Version = "([^"]+)"/)?.[1],
    version,
    'Redactor.Version',
  );
});

test('the published SDK packages ship the licence unchanged', () => {
  const licence = read('LICENSE');
  assert.equal(read('sdk/python/LICENSE'), licence, 'sdk/python/LICENSE');
  assert.equal(read('sdk/rust/LICENSE'), licence, 'sdk/rust/LICENSE');
});
