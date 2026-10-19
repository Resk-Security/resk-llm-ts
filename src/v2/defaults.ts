import { SecurityPipeline, type PipelineOptions } from './core/pipeline.js';
import type { SecurityConfig } from './core/config.js';
import type { BaseDetector } from './core/detector.js';
import {
    DirectInjectionDetector,
    BypassDetectionDetector,
    MemoryPoisoningDetector,
    GoalHijackDetector,
    ExfiltrationDetector,
    InterAgentInjectionDetector,
    VectorSimilarityDetector,
    AclDecisionTreeDetector,
    ContentFramingDetector,
    IndirectInjectionDetector,
    DocumentInjectionDetector,
} from './detectors/index.js';

/**
 * Every built-in detector, in a stable order. Shared instances are stateless
 * and safe to reuse between pipelines.
 */
export const defaultDetectors: ReadonlyArray<BaseDetector> = [
    DirectInjectionDetector,
    BypassDetectionDetector,
    MemoryPoisoningDetector,
    GoalHijackDetector,
    ExfiltrationDetector,
    InterAgentInjectionDetector,
    new VectorSimilarityDetector(),
    new AclDecisionTreeDetector(),
    ContentFramingDetector,
    IndirectInjectionDetector,
    DocumentInjectionDetector,
];

/**
 * Build a {@link SecurityPipeline} pre-loaded with every built-in detector.
 * This is what the middleware and the OpenAI wrapper fall back to, so a default
 * setup is actually protected instead of silently doing nothing.
 */
export function createDefaultPipeline(
    config?: SecurityConfig,
    options?: PipelineOptions,
): SecurityPipeline {
    return new SecurityPipeline(config, options).addAll(defaultDetectors);
}
