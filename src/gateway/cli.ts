/**
 * `flare-redact gateway` — run the sidecar.
 *
 * Everything is configurable three ways because the three deployments differ:
 * a config file for a real installation, environment variables for a container,
 * and flags for the thirty seconds when you are trying it out.
 */

import { readFileSync } from 'node:fs';

import {
  configFromEnv,
  resolveConfig,
  GatewayConfigError,
  DEFAULT_PORT,
  type GatewayConfig,
  type RawConfig,
} from './config.js';
import { createGateway } from './server.js';
import type { RedactOptions } from '../index.js';

export const GATEWAY_HELP = `flare-redact gateway — redact what leaves your network, without touching your code

USAGE
  flare-redact gateway [options]

  Point a vendor SDK's base URL at this process. Request bodies are redacted on
  the way out and the originals are restored in the reply, streaming included.

OPTIONS
  --config <file>       JSON configuration file
  --host <host>         bind address (default: 127.0.0.1)
  --port <n>            bind port (default: ${DEFAULT_PORT})
  --upstream <url>      forward everything to this origin
  --route <prefix=url>  add a prefixed route (repeatable)
  --paths <a,b>         only redact these JSON body paths
                        (e.g. 'messages[*].content,input,prompt')
  --only <ids>          use only these detectors
  --enable <ids>        turn on extra detectors (e.g. pii,phone)
  --disable <ids>       turn off detectors
  --mode <m>            mask | label | hash | pseudonym | surrogate
  --token-env <n>       env var holding the API bearer token
                        (default: FLARE_GATEWAY_TOKEN)
  --no-restore          do not put originals back into responses
  --no-metrics          disable the /metrics endpoint
  --redact-text         also redact form and text/* request bodies
  --log <level>         silent | info | debug (default: info)
  --print-config        print the resolved configuration and exit
  -h, --help            show this help

ENVIRONMENT
  FLARE_UPSTREAM, FLARE_GATEWAY_HOST, FLARE_GATEWAY_PORT, FLARE_GATEWAY_TOKEN,
  FLARE_REDACT_ONLY, FLARE_REDACT_ENABLE, FLARE_REDACT_DISABLE,
  FLARE_REDACT_MODE, FLARE_REDACT_SECRET, FLARE_GATEWAY_MAX_BODY_BYTES,
  FLARE_GATEWAY_TIMEOUT_MS, FLARE_GATEWAY_SESSION_TTL_MS, FLARE_GATEWAY_LOG

EXAMPLES
  flare-redact gateway --upstream https://api.openai.com --enable pii
  flare-redact gateway --route /openai=https://api.openai.com \\
                       --route /anthropic=https://api.anthropic.com
  flare-redact gateway --config flare-gateway.json

  # then, in your application — no other change
  export OPENAI_BASE_URL=http://127.0.0.1:${DEFAULT_PORT}/openai/v1
`;

function csv(value: string | undefined, flag: string): string[] {
  if (!value) throw new GatewayConfigError(`${flag} requires a comma-separated list`);
  const items = value.split(',').map((item) => item.trim()).filter(Boolean);
  if (!items.length) throw new GatewayConfigError(`${flag} requires at least one value`);
  return items;
}

function required(value: string | undefined, flag: string): string {
  if (value === undefined) throw new GatewayConfigError(`${flag} requires a value`);
  return value;
}

/** Parse gateway flags into a config layer. Throws {@link GatewayConfigError}. */
export function parseGatewayArgs(argv: string[]): { raw: RawConfig; help: boolean; printConfig: boolean; tokenEnv: string; configFile?: string } {
  const raw: RawConfig = {};
  const policy: RedactOptions = {};
  const routes: NonNullable<RawConfig['routes']> = [];
  let help = false;
  let printConfig = false;
  let tokenEnv = 'FLARE_GATEWAY_TOKEN';
  let configFile: string | undefined;
  let paths: string[] | undefined;
  let restore = true;
  let redactText = false;

  for (let index = 0; index < argv.length; index++) {
    const flag = argv[index]!;
    switch (flag) {
      case '-h': case '--help': help = true; break;
      case '--print-config': printConfig = true; break;
      case '--config': configFile = required(argv[++index], '--config'); break;
      case '--host': raw.listen = { ...raw.listen, host: required(argv[++index], '--host') }; break;
      case '--port': raw.listen = { ...raw.listen, port: Number(required(argv[++index], '--port')) }; break;
      case '--upstream': raw.upstream = required(argv[++index], '--upstream'); break;
      case '--route': {
        const value = required(argv[++index], '--route');
        const separator = value.indexOf('=');
        if (separator < 1) throw new GatewayConfigError(`--route expects <prefix>=<upstream>, received ${JSON.stringify(value)}`);
        routes.push({ prefix: value.slice(0, separator), upstream: value.slice(separator + 1) });
        break;
      }
      case '--paths': paths = csv(argv[++index], '--paths'); break;
      case '--only': policy.only = csv(argv[++index], '--only'); break;
      case '--enable': policy.enable = csv(argv[++index], '--enable'); break;
      case '--disable': policy.disable = csv(argv[++index], '--disable'); break;
      case '--mode': policy.mode = required(argv[++index], '--mode') as RedactOptions['mode']; break;
      case '--token-env': tokenEnv = required(argv[++index], '--token-env'); break;
      case '--no-restore': restore = false; break;
      case '--no-metrics': raw.metrics = false; break;
      case '--redact-text': redactText = true; break;
      case '--log': raw.log = required(argv[++index], '--log') as GatewayConfig['log']; break;
      default:
        throw new GatewayConfigError(`unknown option: ${flag}`);
    }
  }

  if (Object.keys(policy).length) raw.policy = policy;
  if (routes.length) raw.routes = routes;

  // Flags that describe *how* to treat a body apply to every route the flags
  // themselves declared, and to the shorthand `--upstream` route.
  const perRoute = { ...(paths ? { paths } : {}), ...(redactText ? { nonJson: true } : {}) };
  if (Object.keys(perRoute).length || !restore) {
    const shape = {
      ...(Object.keys(perRoute).length ? { request: { ...perRoute, enabled: true } } : {}),
      ...(restore ? {} : { response: { enabled: false, streamEscape: 'json' as const } }),
    };
    if (raw.routes) raw.routes = raw.routes.map((route) => ({ ...route, ...shape }));
    else if (raw.upstream) raw.routes = [{ prefix: '/', upstream: raw.upstream, ...shape }];
  }

  return { raw, help, printConfig, tokenEnv, ...(configFile ? { configFile } : {}) };
}

function readConfigFile(path: string): RawConfig {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new GatewayConfigError(`cannot read ${path}: ${(error as Error).message}`);
  }
  try {
    return JSON.parse(text) as RawConfig;
  } catch (error) {
    throw new GatewayConfigError(`${path} is not valid JSON: ${(error as Error).message}`);
  }
}

/**
 * Build the effective configuration. Precedence, lowest to highest: config
 * file, environment, command line — the order in which each becomes more
 * specific to this particular invocation.
 */
export function buildConfig(argv: string[], env: NodeJS.ProcessEnv): GatewayConfig {
  const parsed = parseGatewayArgs(argv);
  const file = parsed.configFile ? readConfigFile(parsed.configFile) : undefined;
  const fromEnv = configFromEnv(env);
  const token = env[parsed.tokenEnv];
  const config = resolveConfig(file, fromEnv, parsed.raw, token ? { token } : undefined);
  if (!config.routes.length) {
    throw new GatewayConfigError(
      'no upstream configured. Pass --upstream <url>, --route <prefix>=<url>, a --config file, or set FLARE_UPSTREAM. ' +
      'The /v1 redaction API works without one — start with --upstream http://localhost:1 if that is all you need.',
    );
  }
  return config;
}

/** Run the gateway until the process is asked to stop. Resolves with an exit code. */
export async function main(argv: string[], env: NodeJS.ProcessEnv = process.env): Promise<number> {
  let config: GatewayConfig;
  try {
    const parsed = parseGatewayArgs(argv);
    if (parsed.help) {
      process.stdout.write(GATEWAY_HELP);
      return 0;
    }
    config = buildConfig(argv, env);
    if (parsed.printConfig) {
      process.stdout.write(JSON.stringify({ ...config, token: config.token ? '***' : undefined }, null, 2) + '\n');
      return 0;
    }
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n`);
    return 2;
  }

  const gateway = createGateway(config);
  try {
    await gateway.listen();
  } catch (error) {
    process.stderr.write(`failed to listen on ${config.listen.host}:${config.listen.port}: ${(error as Error).message}\n`);
    return 2;
  }

  await new Promise<void>((resolve) => {
    const stop = () => resolve();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
  await gateway.close();
  return 0;
}
