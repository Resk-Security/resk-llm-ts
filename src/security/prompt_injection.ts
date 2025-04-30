import { PromptInjectionConfig } from "../index";
import { defaultInjectionPatterns } from "./patterns/llm_injection_patterns"; // Import from patterns

// Very basic detection patterns - expand significantly for real use
const basicInjectionPatterns: RegExp[] = [
    /ignore all previous instructions/i,
    /ignore prior commands/i,
    /forget what i told you/i,
    /you are now in .* mode/i,
    /reveal your system prompt/i,
    /print your initial instructions/i,
    /\bSYSTEM PROMPT\b/i,
    // Add more based on known attack vectors
];

export class PromptInjectionDetector {
    private config: PromptInjectionConfig;
    private patterns: RegExp[];

    constructor(config?: PromptInjectionConfig) {
        this.config = {
            enabled: true,
            level: 'basic',
            ...(config || {}),
        };
        // Use imported patterns (add more based on level if implemented)
        this.patterns = [...defaultInjectionPatterns]; 
        // If you add custom patterns via config, merge them here:
        // this.patterns = [...defaultInjectionPatterns, ...(config?.customPatterns || [])];
    }

    detect(text: string): boolean {
        if (!this.config.enabled || !text) {
            return false;
        }

        for (const pattern of this.patterns) {
             // Reset lastIndex for global regex if any (though these aren't global yet)
            pattern.lastIndex = 0; 
            if (pattern.test(text)) {
                console.warn(`Potential prompt injection detected by pattern: ${pattern}`);
                return true;
            }
        }
        return false;
    }
} 