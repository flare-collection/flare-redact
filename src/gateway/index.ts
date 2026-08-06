/**
 * `flare-redact/gateway` — the sidecar, as a library.
 *
 * Import this to embed the proxy in an existing Node service, to write tests
 * against it, or to build a differently-shaped deployment. The CLI in
 * `flare-redact gateway` is a thin wrapper over exactly these exports.
 *
 *   import { resolveConfig, createGateway } from 'flare-redact/gateway';
 *
 *   const gateway = createGateway(resolveConfig({
 *     upstream: 'https://api.openai.com',
 *     policy: { enable: ['pii'] },
 *   }));
 *   await gateway.listen();
 */

export {
  resolveConfig,
  configFromEnv,
  matchRoute,
  upstreamUrl,
  GatewayConfigError,
  DEFAULT_PORT,
  RESERVED_PREFIXES,
  type GatewayConfig,
  type RawConfig,
  type RawRoute,
  type RouteConfig,
  type ListenConfig,
  type RequestRedactionConfig,
  type ResponseRestorationConfig,
} from './config.js';

export {
  parsePath,
  transformAtPath,
  transformAtPaths,
  redactBody,
  restoreBody,
  streamRestorer,
  jsonEscapedEntries,
  isJsonType,
  isFormType,
  isTextType,
  isEventStream,
  PathSyntaxError,
  type ParsedPath,
  type PathSegment,
  type BodyRedactionOptions,
  type BodyRedactionResult,
} from './body.js';

export {
  SessionStore,
  Metrics,
  createLogger,
  type Logger,
  type LogLevel,
  type SessionRecord,
  type SessionStoreOptions,
} from './runtime.js';

export { createGateway, type Gateway } from './server.js';

export { main as runGateway, buildConfig, parseGatewayArgs, GATEWAY_HELP } from './cli.js';
