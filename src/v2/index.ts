// resk-llm-ts v2.1 - Main entry point for enhanced security module

// Core
export { DetectionResult, Severity, ThreatCategory, type BaseDetector, type DetectorMatch } from './core/detector';
export { SecurityPipeline, type PipelineResult } from './core/pipeline';
export { DEFAULT_CONFIG, type SecurityConfig, type ThreatThreshold, type DetectorSection } from './core/config';
export { ConversationContext, type ConversationEntry } from './core/context';
export { RESKError, DetectionError, PipelineError, ConfigurationError } from './core/exceptions';

// Detectors
export * from './detectors';

// Pattern loader
export { loadPatternConfig, loadSection, compilePatterns, getPatternValue } from './core/pattern_loader';
