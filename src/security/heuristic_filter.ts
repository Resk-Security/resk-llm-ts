import { SecurityFeatureConfig } from "../index";
import { defaultInjectionPatterns } from "./patterns/llm_injection_patterns"; // Import default injection patterns

// Combine multiple pattern sources for heuristics if needed
const defaultSuspiciousPatterns: RegExp[] = [
    ...defaultInjectionPatterns, // Include injection patterns as suspicious
    // Add any other general heuristic patterns here if necessary
    /\bsecret\s+key\b/i,
    /\bconfidential\b/i,
];

export interface HeuristicFilterConfig extends SecurityFeatureConfig {
    patterns?: RegExp[];
}

export class HeuristicFilter {
    private config: HeuristicFilterConfig;
    private patterns: RegExp[];

    constructor(config?: HeuristicFilterConfig) {
        this.config = {
            enabled: true,
            ...(config || {}),
        };
        // Use imported defaults + user-provided patterns
        this.patterns = [...defaultSuspiciousPatterns, ...(this.config.patterns || [])];
    }

    /**
     * Add a custom suspicious pattern (regex).
     */
    addSuspiciousPattern(pattern: RegExp): void {
        this.patterns.push(pattern);
    }

    /**
     * Filter the input text based on heuristic patterns.
     * @returns { detected: boolean; reason: string | null } - Whether a pattern was detected and why.
     */
    filter(text: string): { detected: boolean; reason: string | null } {
        if (!this.config.enabled || !text) {
            return { detected: false, reason: null };
        }

        for (const pattern of this.patterns) {
            pattern.lastIndex = 0; // Reset state for global regex
            if (pattern.test(text)) {
                const reason = `Matched heuristic pattern: ${pattern.toString()}`;
                console.warn(`Heuristic filter triggered: ${reason}`);
                return { detected: true, reason: reason };
            }
        }

        return { detected: false, reason: null };
    }
} 