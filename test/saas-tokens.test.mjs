import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, scan, isClean } from '../dist/index.js';

// The classic 40-char example secret from the AWS documentation.
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

test('aws_secret_key catches assignments in env, JSON, and camelCase forms', () => {
  const samples = [
    `AWS_SECRET_ACCESS_KEY=${AWS_SECRET}`,
    `aws_secret_key: ${AWS_SECRET}`,
    `"secretAccessKey": "${AWS_SECRET}"`,
  ];
  for (const sample of samples) {
    const [finding] = scan(sample);
    assert.equal(finding.detector, 'aws_secret_key', sample);
    assert.equal(redact(sample).includes(AWS_SECRET), false, sample);
  }
});

test('aws_secret_key needs context — a bare 40-char string stays clean', () => {
  assert.ok(isClean(`downloaded blob ${AWS_SECRET} from cache`));
});

test('aws_secret_key wins overlap against generic_assignment', () => {
  const findings = scan(`aws_secret_access_key = ${AWS_SECRET}`);
  assert.deepEqual(findings.map((f) => f.detector), ['aws_secret_key']);
});

const TOKENS = [
  ['huggingface_token', 'hf_' + 'AbCd1234'.repeat(4) + 'Xy'],
  ['vault_token', 'hvs.' + 'CAESIJx'.repeat(4)],
  ['groq_key', 'gsk_' + 'Ab12Cd34'.repeat(6) + 'WxYz'],
  ['xai_key', 'xai-' + 'token1AB'.repeat(10)],
  ['perplexity_key', 'pplx-' + 'a1b2c3d4'.repeat(6)],
  ['openrouter_key', 'sk-or-v1-' + 'ab12'.repeat(16)],
  ['replicate_token', 'r8_' + 'Ab12Cd34'.repeat(4) + 'Wxyz5'],
  ['databricks_token', 'dapi' + 'a1b2c3d4'.repeat(4)],
  ['airtable_pat', 'pat' + 'Ab12Cd34Ef56Gh'.slice(0, 14) + '.' + 'ab12cd34'.repeat(8)],
  ['postman_key', 'PMAK-' + 'a1b2c3d4'.repeat(3) + '-' + 'ef56ab12cd34'.repeat(2) + 'a1b2c3d4ef'],
  ['linear_key', 'lin_api_' + 'Ab12Cd34'.repeat(5)],
  ['figma_token', 'figd_' + 'Ab12-Cd34_Ef56Gh78'.repeat(2) + 'Ij90'],
  ['notion_token', 'ntn_' + 'Ab12Cd34'.repeat(5) + 'Wxyz56'],
  ['notion_token', 'secret_' + 'Ab12Cd34Ef5'.repeat(4).slice(0, 43)],
  ['doppler_token', 'dp.st.prd_backend.' + 'Ab12Cd34'.repeat(5)],
  ['supabase_key', 'sbp_' + 'ab12cd34'.repeat(5)],
  ['netlify_token', 'nfp_' + 'Ab12Cd34'.repeat(5)],
  ['stripe_webhook_secret', 'whsec_' + 'Ab12Cd34'.repeat(5)],
  ['mailgun_key', 'key-' + 'ab12cd34'.repeat(4)],
  ['discord_webhook', 'https://discord.com/api/webhooks/123456789012345678/' + 'Ab12Cd34_-'.repeat(7)],
];

test('every new service token is detected under its own id and masked', () => {
  for (const [id, token] of TOKENS) {
    const text = `deploy log: ${token} done`;
    const [finding] = scan(text);
    assert.ok(finding, `${id}: no finding`);
    assert.equal(finding.detector, id, `${id}: got ${finding.detector}`);
    assert.equal(redact(text).includes(token), false, `${id}: token survived redact`);
  }
});

test('GCP service-account key ids and refresh tokens are caught by default', () => {
  const blob = `{"type": "service_account", "private_key_id": "${'ab12cd34'.repeat(5)}"}`;
  const [finding] = scan(blob);
  assert.equal(finding.detector, 'gcp_service_account');
  assert.equal(redact(blob).includes('ab12cd34'), false);

  const refresh = '1//' + 'Ab12Cd34_-'.repeat(4);
  assert.equal(scan(`token ${refresh}`)[0].detector, 'gcp_refresh_token');
  assert.equal(redact(`token ${refresh}`).includes(refresh), false);
});

test('OpenRouter and Anthropic keys never fall through to openai_key', () => {
  const openrouter = 'sk-or-v1-' + 'ab12'.repeat(16);
  const anthropic = 'sk-ant-api03-' + 'a1B2'.repeat(23) + 'A';
  assert.equal(scan(`k=${openrouter}`)[0].detector, 'openrouter_key');
  assert.equal(scan(`k=${anthropic}`)[0].detector, 'anthropic_key');
  assert.equal(scan('k=sk-' + 'x'.repeat(48))[0].detector, 'openai_key');
});

// Tokens are assembled at run time so no complete credential sits in the source.
const B58 = 'Ab12Cd34';
const MORE_TOKENS = [
  ['slack_webhook', 'https://hooks.slack.com/services/T' + 'A1B2C3D4E' + '/B' + 'A1B2C3D4E' + '/' + B58.repeat(3)],
  ['slack_webhook', 'https://hooks.slack.com/triggers/T' + 'A1B2C3D4E' + '/' + '1234567890123' + '/' + 'ab12cd34'.repeat(4)],
  ['google_oauth_secret', 'GOCSPX-' + 'Ab12-Cd34_Ef56Gh78Ij90Kl12Mn'],
  ['aws_bedrock_key', 'ABSK' + 'QmVkcm9ja0FQSUtleS' + B58.repeat(14) + '='],
  ['langsmith_key', 'lsv2_pt_' + 'ab12cd34'.repeat(4) + '_' + 'ab12cd34ef'],
  ['langsmith_key', 'lsv2_sk_' + 'ab12cd34'.repeat(4) + '_' + 'ab12cd34ef'],
  ['pinecone_key', 'pcsk_' + 'Ab1Cd' + '_' + B58.repeat(8)],
  ['tavily_key', 'tvly-' + B58.repeat(4)],
  ['tavily_key', 'tvly-dev-' + B58.repeat(4)],
  ['pypi_token', 'pypi-' + 'AgEIcHlwaS5vcmc' + 'CJGI4Yz' + 'Ab12-Cd34_'.repeat(8)],
  ['pypi_token', 'pypi-' + 'AgENdGVzdC5weXBpLm9yZw' + 'CJGI4Yz' + 'Ab12-Cd34_'.repeat(8)],
  ['rubygems_key', 'rubygems_' + 'ab12cd34'.repeat(6)],
  ['dockerhub_token', 'dckr_pat_' + 'Ab12-Cd34_Ef56Gh78Ij90Kl12M'],
  ['dockerhub_token', 'dckr_oat_' + B58.repeat(4)],
  ['jfrog_token', 'AKCp' + B58.repeat(9).slice(0, 69)],
  ['jfrog_token', 'cmVmd' + B58.repeat(8).slice(0, 59)],
  ['atlassian_token', 'ATATT3' + 'xFfGF0Ab12-Cd34_'.repeat(12).slice(0, 177) + '=' + 'AB12CD34'],
  ['grafana_token', 'glsa_' + B58.repeat(4) + '_' + 'ab12cd34'],
  ['grafana_token', 'glc_' + 'eyJvIjoiMTIz' + B58.repeat(5) + '=='],
  ['sentry_auth_token', 'sntryu_' + 'ab12cd34'.repeat(8)],
  ['sentry_auth_token', 'sntrys_' + 'eyJpYXQiOjE3MDAwMDAwMDB9' + B58.repeat(4) + '_' + B58.repeat(6).slice(0, 43)],
  ['dynatrace_token', 'dt0c01.' + 'AB12CD34'.repeat(3) + '.' + 'EF56GH78'.repeat(8)],
  ['heroku_api_key', 'HRKU-' + 'AA' + 'Ab12-Cd34_'.repeat(6).slice(0, 58)],
  ['flyio_token', 'fo1_' + 'Ab12-Cd34_'.repeat(5).slice(0, 43)],
  ['flyio_token', 'fm2_' + 'lJPE' + 'Ab12+Cd/34'.repeat(12)],
  ['planetscale_token', 'pscale_tkn_' + 'Ab12-Cd34_'.repeat(4)],
  ['planetscale_token', 'pscale_pw_' + 'Ab12-Cd34_'.repeat(4)],
  ['pulumi_token', 'pul-' + 'ab12cd34'.repeat(5)],
  ['terraform_cloud_token', 'Ab12Cd34Ef56Gh' + '.atlasv1.' + 'Ab12-Cd34_'.repeat(7).slice(0, 66)],
  ['onepassword_token', 'ops_eyJ' + B58.repeat(40)],
  ['age_secret_key', 'AGE-SECRET-KEY-1' + 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'.repeat(2).slice(0, 58)],
  ['alibaba_access_key', 'LTAI' + 'Ab12Cd34Ef56Gh78Ij90'],
  ['mailchimp_key', 'ab12cd34'.repeat(4) + '-us21'],
  ['brevo_key', 'xkeysib-' + 'ab12cd34'.repeat(8) + '-' + 'Ab12Cd34Ef56Gh78'],
  ['brevo_key', 'xsmtpsib-' + 'ab12cd34'.repeat(8) + '-' + 'Ab12Cd34Ef56Gh78'],
  ['resend_key', 're_' + B58 + '_' + B58.repeat(3)],
  ['digitalocean_token', 'doo_v1_' + 'ab12cd34'.repeat(8)],
  ['digitalocean_token', 'dor_v1_' + 'ab12cd34'.repeat(8)],
  ['gitlab_token', 'glpat-' + 'Ab12-Cd34_'.repeat(3).slice(0, 27) + '.01' + 'abc1234'],
  ['gitlab_token', 'glrt-t1_' + 'Ab12-Cd34_'.repeat(3).slice(0, 27) + '.01' + 'abc1234'],
  ['gitlab_token', 'gldt-' + 'Ab12-Cd34_Ef56Gh78Ij'],
  ['gitlab_token', 'glrt-' + 'Ab12-Cd34_Ef56Gh78Ij'],
  ['gitlab_token', 'glptt-' + 'ab12cd34'.repeat(5)],
  ['gitlab_token', 'glcbt-' + '64' + '_' + 'Ab12-Cd34_Ef56Gh78Ij'],
  ['gitlab_token', 'glagent-' + 'Ab12-Cd34_'.repeat(5)],
  ['slack_app_token', 'xapp-1-A0123456789-1234567890123-' + 'ab12cd34'.repeat(8)],
  ['twitter_bearer_token', 'A'.repeat(21) + 'Mk9x' + 'Ab12Cd34%2F'.repeat(8)],
  ['meta_access_token', 'EAAG' + 'Ab12Cd34Ef56'.repeat(10)],
  ['mapbox_secret_token', 'sk.eyJ1IjoiYWRhIiwiYSI6ImNrMTIzIn0.' + 'Ab12Cd34Ef56Gh78Ij90Kl'],
  ['contentful_token', 'CFPAT-' + 'Ab12-Cd34_'.repeat(5).slice(0, 43)],
  ['hubspot_token', 'pat-na1-' + '12345678-abcd-4ef0-9abc-1234567890ab'],
  ['sonarqube_token', 'squ_' + 'ab12cd34'.repeat(5)],
  ['buildkite_token', 'bkua_' + 'ab12cd34'.repeat(5)],
  ['plaid_token', 'access-sandbox-' + '12345678-abcd-4ef0-9abc-1234567890ab'],
  ['braintree_token', 'access_token$production$ab12cd34ef56gh78$' + 'ab12cd34'.repeat(4)],
  ['shippo_token', 'shippo_live_' + 'ab12cd34'.repeat(5)],
  ['langfuse_key', 'sk-lf-' + '12345678-abcd-4ef0-9abc-1234567890ab'],
  ['posthog_personal_key', 'phx_' + 'Ab12Cd34Ef56'.repeat(4)],
  ['neon_api_key', 'napi_' + 'ab12cd34'.repeat(8)],
  ['typeform_token', 'tfp_' + 'Ab12Cd34Ef56'.repeat(4)],
  ['readme_key', 'rdme_' + 'ab12cd34ef'.repeat(7)],
  ['prefect_key', 'pnu_' + 'Ab12Cd34Ef56'.repeat(3)],
  ['fcm_server_key', 'AAAA' + 'Ab12Cd3' + ':' + ('APA91b' + 'Ab12-Cd34_'.repeat(14)).slice(0, 140)],
  ['azure_ad_client_secret', 'abc8Q~' + 'Ab12-Cd34_Ef56~Gh78.Ij90Kl12Mn34'],
  ['firecrawl_key', 'fc-' + 'ab12cd34'.repeat(4)],
  ['e2b_key', 'e2b_' + 'ab12cd34'.repeat(5)],
  ['clickup_token', 'pk_12345678_' + 'AB12CD34'.repeat(4)],
  ['flutterwave_key', 'FLWSECK_TEST-' + 'ab12cd34'.repeat(4) + '-X'],
  ['duffel_token', 'duffel_test_' + 'Ab12-Cd34_'.repeat(5).slice(0, 43)],
  ['frameio_token', 'fio-u-' + 'Ab12-Cd34_'.repeat(7).slice(0, 64)],
];

// Strings that look close to a token but are not one. Each must stay untouched.
const NEAR_MISSES = [
  ['slack_webhook', 'https://hooks.slack.com/services/T' + 'A1B2' + '/B0/x'],
  ['google_oauth_secret', 'GOCSPX-' + B58],
  ['aws_bedrock_key', 'ABSK' + B58.repeat(4)],
  ['langsmith_key', 'lsv2_pt_' + 'ab12cd34'.repeat(4)],
  ['pinecone_key', 'pcsk_' + 'Ab1Cd' + '_' + B58],
  ['tavily_key', 'tvly-' + B58],
  ['pypi_token', 'pypi-' + B58.repeat(8)],
  ['rubygems_key', 'rubygems_' + 'ab12cd34'.repeat(5)],
  ['dockerhub_token', 'dckr_pat_' + B58],
  ['jfrog_token', 'AKCp' + B58.repeat(2)],
  ['atlassian_token', 'ATATT3' + 'xFfGF0Ab12'],
  ['grafana_token', 'glsa_' + B58.repeat(4)],
  ['sentry_auth_token', 'sntryu_' + 'ab12cd34'.repeat(4)],
  ['dynatrace_token', 'dt0c01.' + 'AB12CD34'.repeat(3)],
  ['heroku_api_key', 'HRKU-' + B58],
  ['flyio_token', 'fo1_' + B58],
  ['planetscale_token', 'pscale_tkn_' + B58],
  ['pulumi_token', 'pul-' + 'ab12cd34'.repeat(4)],
  ['terraform_cloud_token', 'Ab12Cd34Ef56Gh' + '.atlasv1.' + 'short'],
  ['onepassword_token', 'ops_eyJ' + B58.repeat(4)],
  ['age_secret_key', 'AGE-SECRET-KEY-1' + 'B'.repeat(58)],
  ['alibaba_access_key', 'LTAI' + B58],
  ['mailchimp_key', 'ab12cd34'.repeat(4) + '-us-east-1'],
  ['brevo_key', 'xkeysib-' + 'ab12cd34'.repeat(8)],
  ['resend_key', 're_compute_cache'],
  ['gitlab_token', 'glpat-' + 'Ab12'],
  ['gitlab_token', 'glptt-' + 'xyz'.repeat(14)],
  ['slack_app_token', 'xapp-1-A0123-short'],
  ['twitter_bearer_token', 'A'.repeat(25) + 'Mk9x' + 'Ab12Cd34%2F'.repeat(8)],
  ['twitter_bearer_token', 'A'.repeat(140)],
  ['meta_access_token', 'EAAG' + 'Ab12'.repeat(5)],
  ['mapbox_secret_token', 'pk.eyJ1IjoiYWRhIiwiYSI6ImNrMTIzIn0.' + 'Ab12Cd34Ef56Gh78Ij90Kl'],
  ['contentful_token', 'CFPAT-' + 'short'],
  ['hubspot_token', 'pat-na1-' + 'not-a-uuid'],
  ['sonarqube_token', 'squ_' + 'xyz'.repeat(14)],
  ['buildkite_token', 'bkua_' + 'ab12'],
  ['plaid_token', 'access-sandbox-' + '12345678'],
  ['braintree_token', 'access_token$production$' + 'short'],
  ['shippo_token', 'shippo_live_' + 'xyz'],
  ['langfuse_key', 'pk-lf-' + '12345678-abcd-4ef0-9abc-1234567890ab'],
  ['posthog_personal_key', 'phc_' + 'Ab12Cd34Ef56'.repeat(4)],
  ['neon_api_key', 'napi_' + 'ab12'],
  ['typeform_token', 'tfp_' + 'short'],
  ['readme_key', 'rdme_' + 'ab12'],
  ['prefect_key', 'pnu_' + 'Ab12'],
  ['fcm_server_key', 'AAAA' + 'Ab12Cd3' + ':' + 'short'],
  ['azure_ad_client_secret', 'abc8Q~' + 'short'],
  ['firecrawl_key', 'fc-' + 'xyz'],
  ['e2b_key', 'e2b_' + 'xyz'],
  ['clickup_token', 'pk_12345678_' + 'short'],
  ['flutterwave_key', 'FLWSECK-' + 'zz'],
  ['duffel_token', 'duffel_test_' + 'short'],
  ['frameio_token', 'fio-u-' + 'short'],
];

test('more service tokens are detected under their own id and masked', () => {
  for (const [id, token] of MORE_TOKENS) {
    const text = `deploy log: ${token} done`;
    const findings = scan(text);
    assert.equal(findings.length, 1, `${id}: expected one finding, got ${findings.map((f) => f.detector)}`);
    assert.equal(findings[0].detector, id, `${id}: got ${findings[0].detector}`);
    assert.equal(findings[0].start, 'deploy log: '.length, `${id}: finding does not start at the token`);
    assert.equal(findings[0].end, 'deploy log: '.length + token.length, `${id}: finding does not cover the token`);
    const masked = redact(text);
    assert.equal(masked.includes(token), false, `${id}: token survived redact`);
    assert.ok(masked.startsWith('deploy log: ') && masked.endsWith(' done'), `${id}: ${masked}`);
  }
});

test('near misses of the new service tokens stay clean', () => {
  for (const [id, text] of NEAR_MISSES) {
    const hit = scan(`note ${text} end`).find((f) => f.detector === id);
    assert.equal(hit, undefined, `${id} fired on ${text}`);
  }
});

test('a service token glued to more token characters is not cut short', () => {
  const glued = [
    'dckr_pat_' + 'Ab12-Cd34_Ef56Gh78Ij90Kl12M' + '-more',
    'GOCSPX-' + 'Ab12-Cd34_Ef56Gh78Ij90Kl12Mn' + 'X',
    'glpat-' + 'Ab12-Cd34_'.repeat(3).slice(0, 27) + '.01' + 'abc1234' + 'X',
    'HRKU-' + 'AA' + 'Ab12-Cd34_'.repeat(6).slice(0, 58) + '_',
  ];
  for (const text of glued) assert.deepEqual(scan(`x ${text} y`), [], text);
});

test('masks keep only the token prefix', () => {
  const masked = (token) => redact(`t ${token}`).slice(2);
  assert.equal(masked('pypi-' + 'AgEIcHlwaS5vcmc' + 'Ab12-Cd34_'.repeat(8)), 'pypi-***');
  assert.equal(masked('dckr_pat_' + 'Ab12-Cd34_Ef56Gh78Ij90Kl12M'), 'dckr_pat_***');
  assert.equal(masked('glc_' + 'eyJvIjoiMTIz' + B58.repeat(5)), 'glc_***');
  assert.equal(masked('pscale_tkn_' + 'Ab12-Cd34_'.repeat(4)), 'pscale_tkn_***');
  assert.equal(masked('gldt-' + 'Ab12-Cd34_Ef56Gh78Ij'), 'gldt-***');
  assert.equal(masked('glagent-' + 'Ab12-Cd34_'.repeat(5)), 'glagent-***');
  assert.equal(masked('AGE-SECRET-KEY-1' + 'QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L'.repeat(2).slice(0, 58)), 'AGE-SECRET-KEY-***');
  assert.equal(masked('xsmtpsib-' + 'ab12cd34'.repeat(8) + '-' + 'Ab12Cd34Ef56Gh78'), 'xsmtpsib-***');
  assert.equal(masked('Ab12Cd34Ef56Gh' + '.atlasv1.' + 'Ab12-Cd34_'.repeat(7).slice(0, 66)), '[REDACTED TERRAFORM TOKEN]');
});

test('the portable pack and the built-in detectors agree on every new token and near miss', async () => {
  const { readFileSync } = await import('node:fs');
  const { loadPack } = await import('../dist/pack.js');
  const pack = loadPack(JSON.parse(readFileSync(new URL('../spec/detectors.json', import.meta.url), 'utf8')));
  // Two tokens glued with a dash are left out on purpose: FRS-1 engines do not
  // rewind after a discarded match (SPEC §4), so they can differ from a
  // backtracking lookahead there.
  const samples = [
    ...MORE_TOKENS.map(([, token]) => `deploy log: ${token} done`),
    ...MORE_TOKENS.map(([, token]) => `{"token":"${token}"}`),
    ...MORE_TOKENS.map(([, token]) => `TOKEN=${token}\n`),
    ...MORE_TOKENS.map(([, token]) => `${token}X`),
    ...NEAR_MISSES.map(([, text]) => `note ${text} end`),
  ];
  const view = (findings) => findings.map((f) => [f.detector, f.start, f.end]);
  for (const text of samples) {
    const builtIn = scan(text);
    assert.deepEqual(view(scan(text, { detectors: pack.detectors })), view(builtIn), text);
    // generic_assignment has its own portable mask, so compare the text only
    // where a service token detector made the call.
    if (builtIn.every((f) => f.detector !== 'generic_assignment')) {
      assert.equal(redact(text, { detectors: pack.detectors }), redact(text), text);
    }
  }
});

test('no pack pattern repeats more than 1000 times, the most RE2 accepts', async () => {
  const { readFileSync } = await import('node:fs');
  const pack = JSON.parse(readFileSync(new URL('../spec/detectors.json', import.meta.url), 'utf8'));
  for (const detector of pack.detectors) {
    for (const [, min, max] of detector.pattern.matchAll(/\{(\d+)(?:,(\d*))?\}/g)) {
      assert.ok(Number(min) <= 1000 && (max === undefined || max === '' || Number(max) <= 1000), `${detector.id}: {${min},${max}}`);
    }
  }
});
