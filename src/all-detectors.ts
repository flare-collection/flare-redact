/**
 * The full built-in detector list: the core detectors, then entity recognition.
 * Importing this module installs entity support in the engine.
 */
import { CORE_DETECTORS, type Detector } from './detectors.js';
import { ENTITY_DETECTORS } from './entities.js';

export const DETECTORS: Detector[] = [...CORE_DETECTORS, ...ENTITY_DETECTORS];
