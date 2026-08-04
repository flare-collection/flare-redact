import { redact, type RedactOptions } from './index.js';
import { createVault, restore, type Vault, type VaultOptions } from './vault.js';

export interface ToolBoundary {
  /**
   * Mask an MCP/tool result before it is appended to model context. New
   * placeholders are added to this boundary's conversation-scoped vault.
   */
  redactForModel<T>(result: T): T;
  /** Restore placeholders in a model-produced tool call before execution. */
  restoreForTool<T>(call: T): T;
  /** Restore placeholders in the final model output before showing the app. */
  restoreForApp<T>(output: T): T;
  /** The conversation-scoped placeholder mapping. */
  readonly vault: Vault;
  readonly size: number;
  reset(): void;
}

export interface ScopedToolBoundaryOptions extends Omit<VaultOptions, 'placeholder' | 'placeholderStyle'> {
  /** Maximum number of distinct tool/trust-domain scopes kept at once. Default: 128. */
  maxScopes?: number;
  /** Optional globally unique placeholder formatter. Opaque random placeholders are safer. */
  placeholder?: (scope: string, detectorId: string, index: number) => string;
}

export interface ScopedToolBoundary {
  /** Mask values for model context and bind new placeholders to one restore scope. */
  redactForModel<T>(scope: string, result: T): T;
  /** Restore only placeholders minted inside this exact scope. */
  restoreForTool<T>(scope: string, call: T): T;
  /** Restore every scope for the trusted final application boundary. */
  restoreForApp<T>(output: T): T;
  /** Number of placeholder mappings across all scopes. */
  readonly size: number;
  /** Currently allocated scopes, in insertion order. */
  readonly scopes: readonly string[];
  /** Reset one scope, or every scope when omitted. */
  reset(scope?: string): void;
}

/** One-way redaction for logging or persisting a tool call safely. */
export function redactToolCall<T>(call: T, opts: RedactOptions = {}): T {
  return redact(call, opts);
}

/** One-way redaction for logging or persisting a tool/MCP result safely. */
export function redactToolResult<T>(result: T, opts: RedactOptions = {}): T {
  return redact(result, opts);
}

/** One-way redaction for an arbitrary JSON-RPC/MCP message. */
export function redactMcpMessage<T>(message: T, opts: RedactOptions = {}): T {
  return redact(message, opts);
}

/**
 * Reversible boundary for agent loops:
 *
 * model tool call -> restoreForTool -> execute -> redactForModel -> model
 *
 * Security: this shared vault is intended for one tool or trust domain. For
 * multi-tool agents, use createScopedToolBoundary() so a model cannot move a
 * placeholder into a different tool call and have it restored there.
 */
export function createToolBoundary(opts: VaultOptions = {}): ToolBoundary {
  let vault = createVault(opts);
  return {
    redactForModel: <T>(result: T): T => vault.redact(result),
    restoreForTool: <T>(call: T): T => vault.restore(call),
    restoreForApp: <T>(output: T): T => vault.restore(output),
    get vault() {
      return vault;
    },
    get size() {
      return vault.size;
    },
    reset() {
      vault = createVault(opts);
    },
  };
}

function validateScope(scope: string): string {
  if (typeof scope !== 'string' || scope.length === 0 || scope.length > 256) {
    throw new TypeError('Tool scope must be a non-empty string no longer than 256 characters.');
  }
  return scope;
}

/**
 * Reversible agent boundary with a separate vault per tool or trust domain.
 * A placeholder minted for one scope remains opaque when a model transplants
 * it into another scope's arguments.
 *
 *   boundary.redactForModel('database', result)
 *   boundary.restoreForTool('database', call) // allowed
 *   boundary.restoreForTool('http', call)     // placeholder stays opaque
 */
export function createScopedToolBoundary(
  opts: ScopedToolBoundaryOptions = {},
): ScopedToolBoundary {
  const { maxScopes = 128, placeholder, ...redactOptions } = opts;
  if (!Number.isInteger(maxScopes) || maxScopes < 1 || maxScopes > 10_000) {
    throw new RangeError('maxScopes must be an integer from 1 to 10,000.');
  }

  const vaults = new Map<string, Vault>();
  const placeholderOwners = new Map<string, string>();

  const dropScope = (scope: string): void => {
    const vault = vaults.get(scope);
    if (!vault) return;
    for (const [token] of vault.entries()) {
      if (placeholderOwners.get(token) === scope) placeholderOwners.delete(token);
    }
    vaults.delete(scope);
  };

  const vaultFor = (rawScope: string): Vault => {
    const scope = validateScope(rawScope);
    const existing = vaults.get(scope);
    if (existing) return existing;
    if (vaults.size >= maxScopes) {
      throw new Error(`Scoped tool boundary exceeded its ${maxScopes} scope limit.`);
    }
    const vault = createVault({
      ...redactOptions,
      placeholderStyle: 'opaque',
      ...(placeholder
        ? { placeholder: (detectorId, index) => placeholder(scope, detectorId, index) }
        : {}),
    });
    vaults.set(scope, vault);
    return vault;
  };

  const registerPlaceholders = (scope: string, vault: Vault): void => {
    for (const [token] of vault.entries()) {
      const owner = placeholderOwners.get(token);
      if (owner !== undefined && owner !== scope) {
        throw new Error(`Placeholder generator produced a cross-scope collision for "${token}".`);
      }
      placeholderOwners.set(token, scope);
    }
  };

  return {
    redactForModel<T>(rawScope: string, result: T): T {
      const scope = validateScope(rawScope);
      const vault = vaultFor(scope);
      const redacted = vault.redact(result);
      try {
        registerPlaceholders(scope, vault);
      } catch (error) {
        dropScope(scope);
        throw error;
      }
      return redacted;
    },
    restoreForTool<T>(scope: string, call: T): T {
      const validScope = validateScope(scope);
      return vaults.get(validScope)?.restore(call) ?? call;
    },
    restoreForApp<T>(output: T): T {
      const entries = new Map<string, string>();
      for (const vault of vaults.values()) {
        for (const [token, value] of vault.entries()) entries.set(token, value);
      }
      return restore(output, entries);
    },
    get size() {
      let total = 0;
      for (const vault of vaults.values()) total += vault.size;
      return total;
    },
    get scopes() {
      return Object.freeze([...vaults.keys()]);
    },
    reset(scope?: string): void {
      if (scope === undefined) {
        vaults.clear();
        placeholderOwners.clear();
        return;
      }
      const validScope = validateScope(scope);
      dropScope(validScope);
    },
  };
}
