// resk-llm-ts v2 - Main entry point for the security module

// Core
export { DetectionResult, Severity, ThreatCategory, type BaseDetector, type DetectorMatch } from './core/detector.js';
export { SecurityPipeline, type PipelineResult, type PipelineOptions } from './core/pipeline.js';
export { DEFAULT_CONFIG, type SecurityConfig, type DetectorSection } from './core/config.js';
export { ConversationContext, type ConversationEntry } from './core/context.js';
export { RESKError, DetectionError, PipelineError, ConfigurationError } from './core/exceptions.js';

// Detectors
export * from './detectors/index.js';

// Protection modules
export * from './protection/index.js';

// Integrations (Express, Hono, OpenAI)
export * from './integrations/index.js';

// Ready-to-use pipeline with every built-in detector
export { createDefaultPipeline, defaultDetectors } from './defaults.js';

// Pattern loader
export { loadPatternConfig, reloadPatternConfig, loadSection, compilePatterns, getPatternValue } from './core/pattern_loader.js';
