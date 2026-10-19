export interface DetectorSection {
    enabled: boolean;
    high?: Array<{ name: string; pattern: string; description: string }>;
    medium?: Array<{ name: string; pattern: string; description: string }>;
    low?: Array<{ name: string; pattern: string; description: string }>;
}

export interface SecurityConfig {
    /**
     * Behaviour when a detector throws. `false` (default) fails **closed**: the
     * thrown error is turned into a blocking result. `true` fails open.
     */
    failOpen?: boolean;
    /** Threat categories that always block, regardless of severity. */
    blockCategories?: string[];
    /** Threats below this confidence are ignored for the block decision. */
    minConfidenceThreshold?: number;
    /** Inputs longer than this are rejected before any detector runs. */
    maxInputLength?: number;
    /** Memoize results for repeated, context-less inputs. */
    enableCaching?: boolean;
    /** Maximum number of cached results (FIFO eviction). */
    cacheSize?: number;
}

export const DEFAULT_CONFIG: Required<SecurityConfig> = {
    failOpen: false,
    blockCategories: [
        'direct_injection', 'bypass_detection', 'exfiltration',
        'memory_poisoning', 'inter_agent_injection',
        'indirect_injection', 'document_injection',
    ],
    minConfidenceThreshold: 0.3,
    maxInputLength: 100_000,
    enableCaching: true,
    cacheSize: 10_000,
};
