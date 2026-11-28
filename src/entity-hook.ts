/**
 * Where entity recognition plugs into the engine. `flare-redact` installs it by
 * importing `./entities.js`; `flare-redact/lite` never does, which keeps the
 * name lists out of browser and edge bundles. The engine asks here at call
 * time, so the order modules load in does not matter.
 */
import type { Detector } from './detectors.js';
import type { EntityFinding } from './entities.js';

/** The labels entity recognition emits; also its detector ids. */
export const ENTITY_LABELS = [
  'private_person',
  'private_address',
  'private_phone',
  'private_date',
  'account_number',
  'private_handle',
  'private_url',
  'secret',
] as const;

export interface EntitySupport {
  readonly detectors: readonly Detector[];
  readonly labels: readonly string[];
  isEntityDetector(det: Detector): boolean;
  recognize(text: string, options: Record<string, unknown> & { labels: string[] }): EntityFinding[];
}

let installed: EntitySupport | undefined;

export function installEntitySupport(support: EntitySupport): void {
  installed = support;
}

export function entitySupport(): EntitySupport | undefined {
  return installed;
}
