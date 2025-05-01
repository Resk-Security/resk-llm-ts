/**
 * Represents a function that takes a string and returns its vector embedding.
 */
export type EmbeddingFunction = (text: string) => Promise<number[]>;

/**
 * Represents metadata associated with a vector entry.
 */
export interface VectorMetadata {
    id?: string | number;
    [key: string]: unknown; // Fix: use unknown instead of any
}

/**
 * Represents a single entry in the vector database.
 */
export interface VectorEntry {
    id: string; // Unique identifier for the entry
    vector: number[];
    metadata: VectorMetadata;
}

/**
 * Result of a similarity search or detection.
 */
export interface SimilarityResult {
    detected: boolean;
    max_similarity: number;
    similar_entries: VectorEntry[];
}

// --- Configuration Interfaces --- 

/** Base config for features that are just enabled/disabled */
export interface SecurityFeatureConfig {
    enabled: boolean;
}

/** PII Detection Configuration */
export interface PIIDetectionConfig extends SecurityFeatureConfig {
    redact?: boolean;
    patterns?: RegExp[];
}

/** Input Sanitization Configuration */
export interface InputSanitizationConfig extends SecurityFeatureConfig {
    // Add properties to fix empty interface error
    sanitizeHtml?: boolean;
    allowedTags?: string[];
}

/** Prompt Injection Detection Configuration */
export interface PromptInjectionConfig extends SecurityFeatureConfig {
    level?: 'basic' | 'advanced'; // Example levels
    // Add custom pattern options etc. if needed
}

/** Heuristic Filter Configuration */
export interface HeuristicFilterConfig extends SecurityFeatureConfig {
    // Add properties to fix empty interface error
    customPatterns?: RegExp[];
    severity?: 'low' | 'medium' | 'high';
}

/** Vector Database Configuration */
export interface VectorDBConfig extends SecurityFeatureConfig {
    embeddingFunction: EmbeddingFunction;
    similarityThreshold?: number;
}

/** Canary Token Configuration */
export interface CanaryTokenConfig extends SecurityFeatureConfig {
    // Add properties to fix empty interface error
    tokenPrefix?: string;
    includeContextInWarnings?: boolean;
}

/** Main security configuration combining all features */
export interface ReskSecurityConfig {
    inputSanitization?: InputSanitizationConfig;
    piiDetection?: PIIDetectionConfig;
    promptInjection?: PromptInjectionConfig;
    heuristicFilter?: HeuristicFilterConfig;
    vectorDb?: Omit<VectorDBConfig, 'embeddingFunction'>; // Embedding fn managed by client
    canaryTokens?: CanaryTokenConfig;
    contentModeration?: SecurityFeatureConfig; // Placeholder
} 