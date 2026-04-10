export interface ThreatThreshold {
    criticalFromCount: number;
    highBase: number;
    highIncrement: number;
    mediumBase: number;
    mediumIncrement: number;
    lowBase: number;
    lowIncrement: number;
}

export interface DetectorSection {
    enabled: boolean;
    high?: Array<{ name: string; pattern: string; description: string }>;
    medium?: Array<{ name: string; pattern: string; description: string }>;
    low?: Array<{ name: string; pattern: string; description: string }>;
}

export interface SecurityConfig {
    failOpen?: boolean;
    blockCategories?: string[];
    minConfidenceThreshold?: number;
    blockScoreThreshold?: number;
    languages?: string[];
    maxInputLength?: number;
    enableCaching?: boolean;
    cacheSize?: number;
    logLevel?: string;
    thresholds?: Record<string, ThreatThreshold>;
}

export const DEFAULT_CONFIG: Required<SecurityConfig> = {
    failOpen: false,
    blockCategories: [
        'direct_injection', 'bypass_detection', 'exfiltration',
        'memory_poisoning', 'inter_agent_injection',
    ],
    minConfidenceThreshold: 0.3,
    blockScoreThreshold: 5.0,
    languages: ['en', 'fr'],
    maxInputLength: 100_000,
    enableCaching: true,
    cacheSize: 10_000,
    logLevel: 'WARNING',
    thresholds: {
        direct_injection: {
            criticalFromCount: 2,
            highBase: 0.5, highIncrement: 0.15,
            mediumBase: 0.3, mediumIncrement: 0.1,
            lowBase: 0.2, lowIncrement: 0.05,
        },
        bypass_detection: {
            criticalFromCount: 2,
            highBase: 0.5, highIncrement: 0.1,
            mediumBase: 0.3, mediumIncrement: 0.15,
            lowBase: 0.2, lowIncrement: 0.05,
        },
        memory_poisoning: {
            criticalFromCount: 2,
            highBase: 0.4, highIncrement: 0.1,
            mediumBase: 0.3, mediumIncrement: 0.1,
            lowBase: 0.2, lowIncrement: 0.05,
        },
        goal_hijack: {
            criticalFromCount: 2,
            highBase: 0.5, highIncrement: 0.1,
            mediumBase: 0.3, mediumIncrement: 0.1,
            lowBase: 0.2, lowIncrement: 0.05,
        },
        exfiltration: {
            criticalFromCount: 2,
            highBase: 0.5, highIncrement: 0.1,
            mediumBase: 0.3, mediumIncrement: 0.1,
            lowBase: 0.2, lowIncrement: 0.05,
        },
        inter_agent_injection: {
            criticalFromCount: 2,
            highBase: 0.5, highIncrement: 0.1,
            mediumBase: 0.3, mediumIncrement: 0.1,
            lowBase: 0.2, lowIncrement: 0.05,
        },
        vector_similarity: {
            criticalFromCount: 1,
            highBase: 0.5, highIncrement: 0.15,
            mediumBase: 0.3, mediumIncrement: 0.1,
            lowBase: 0.2, lowIncrement: 0.05,
        },
        content_framing: {
            criticalFromCount: 2,
            highBase: 0.5, highIncrement: 0.1,
            mediumBase: 0.35, mediumIncrement: 0.08,
            lowBase: 0.15, lowIncrement: 0.08,
        },
    },
};
