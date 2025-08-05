/**
 * Custom security exception thrown when security violations are detected.
 */
export class SecurityException extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SecurityException';
    }
}

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
    scoreThreshold?: number;
    industryProfile?: 'general' | 'healthcare' | 'finance' | 'education' | 'government';
    enableContextualAnalysis?: boolean;
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

/** Content Moderation Configuration */
export interface ContentModerationConfig extends SecurityFeatureConfig {
    severity?: 'low' | 'medium' | 'high';
    actions?: {
        toxic?: 'block' | 'warn' | 'redact' | 'log';
        adult?: 'block' | 'warn' | 'redact' | 'log';
        violence?: 'block' | 'warn' | 'redact' | 'log';
        selfHarm?: 'block' | 'warn' | 'redact' | 'log';
        misinformation?: 'block' | 'warn' | 'redact' | 'log';
    };
    customPatterns?: {
        category: string;
        patterns: RegExp[];
        action: 'block' | 'warn' | 'redact' | 'log';
    }[];
    languageSupport?: string[];
    contextAware?: boolean;
}

/** Main security configuration combining all features */
export interface ReskSecurityConfig {
    inputSanitization?: InputSanitizationConfig;
    piiDetection?: PIIDetectionConfig;
    promptInjection?: PromptInjectionConfig;
    heuristicFilter?: HeuristicFilterConfig;
    vectorDb?: Omit<VectorDBConfig, 'embeddingFunction'>; // Embedding fn managed by client
    canaryTokens?: CanaryTokenConfig;
    contentModeration?: ContentModerationConfig; // Now fully implemented
} 

/**
 * Interface générique pour une base de données vectorielle (custom DB, Pinecone, etc.)
 */
export interface IVectorDatabase {
    isEnabled(): boolean;
    addTextEntry(text: string, metadata?: VectorMetadata): Promise<string | null>;
    addEntry(vector: number[], metadata?: VectorMetadata): string | null;
    searchSimilarText(text: string, k?: number, threshold?: number): Promise<SimilarityResult>;
    searchSimilarVector(queryVector: number[], k?: number, threshold?: number): SimilarityResult;
    detect(text: string): Promise<SimilarityResult>;
} 