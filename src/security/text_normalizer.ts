/**
 * Text normalization utilities for security pattern matching
 * Helps detect obfuscated and disguised malicious content
 */

export interface TextNormalizationConfig {
    enabled: boolean;
    normalizeUnicode?: boolean;
    normalizeSpacing?: boolean;
    normalizeCase?: boolean;
    normalizeObfuscation?: boolean;
    normalizeHomoglyphs?: boolean;
}

export class TextNormalizer {
    private config: TextNormalizationConfig;

    // Common character substitutions used for obfuscation
    private readonly homoglyphs: Record<string, string> = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't',
        '@': 'a', '!': 'i', '$': 's', '€': 'e', '£': 'l',
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', // Cyrillic
        'ａ': 'a', 'ｅ': 'e', 'ｉ': 'i', 'ｏ': 'o', 'ｕ': 'u', // Fullwidth
    };

    // Common obfuscation patterns
    private readonly obfuscationPatterns: Array<{pattern: RegExp, replacement: string}> = [
        { pattern: /\[dot\]/gi, replacement: '.' },
        { pattern: /\[at\]/gi, replacement: '@' },
        { pattern: /\s+at\s+/gi, replacement: '@' },
        { pattern: /\s+dot\s+/gi, replacement: '.' },
        { pattern: /\[.\]/g, replacement: '.' }, // [.] -> .
        { pattern: /\[@\]/g, replacement: '@' }, // [@] -> @
        { pattern: /hxxp/gi, replacement: 'http' },
        { pattern: /[[\]]/g, replacement: '' }, // Remove brackets
    ];

    constructor(config?: Partial<TextNormalizationConfig>) {
        this.config = {
            enabled: true,
            normalizeUnicode: true,
            normalizeSpacing: true,
            normalizeCase: true,
            normalizeObfuscation: true,
            normalizeHomoglyphs: true,
            ...config
        };
    }

    /**
     * Normalize text for security pattern matching
     */
    normalize(text: string): string {
        if (!this.config.enabled || !text) {
            return text;
        }

        let normalized = text;

        // 1. Unicode normalization
        if (this.config.normalizeUnicode) {
            normalized = normalized.normalize('NFKC');
        }

        // 2. Case normalization
        if (this.config.normalizeCase) {
            normalized = normalized.toLowerCase();
        }

        // 3. Spacing normalization
        if (this.config.normalizeSpacing) {
            // Use non-backtracking approach to prevent ReDoS
            normalized = normalized
                .split(/\s+/).filter(Boolean).join(' ') // Multiple spaces to single (ReDoS-safe)
                .replace(/\s*([.@:])\s*/g, '$1') // Remove spaces around special chars
                .trim();
        }

        // 4. Obfuscation pattern normalization
        if (this.config.normalizeObfuscation) {
            for (const {pattern, replacement} of this.obfuscationPatterns) {
                normalized = normalized.replace(pattern, replacement);
            }
        }

        // 5. Homoglyph normalization
        if (this.config.normalizeHomoglyphs) {
            for (const [obfuscated, normal] of Object.entries(this.homoglyphs)) {
                // Escape special regex characters
                const escaped = obfuscated.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const regex = new RegExp(escaped, 'g');
                normalized = normalized.replace(regex, normal);
            }
        }

        return normalized;
    }

    /**
     * Create multiple normalized variants of text for comprehensive matching
     */
    createVariants(text: string): string[] {
        const variants = [text];
        
        if (!this.config.enabled) {
            return variants;
        }

        // Add fully normalized version
        variants.push(this.normalize(text));

        // Add partial normalizations for edge cases
        const partialConfigs = [
            { normalizeObfuscation: true, normalizeHomoglyphs: false },
            { normalizeObfuscation: false, normalizeHomoglyphs: true },
            { normalizeSpacing: true, normalizeCase: false },
        ];

        for (const partialConfig of partialConfigs) {
            const tempNormalizer = new TextNormalizer({ ...this.config, ...partialConfig });
            const variant = tempNormalizer.normalize(text);
            if (!variants.includes(variant)) {
                variants.push(variant);
            }
        }

        return variants;
    }

    /**
     * Test if text matches pattern after normalization
     */
    testPattern(text: string, pattern: RegExp): boolean {
        const variants = this.createVariants(text);
        
        for (const variant of variants) {
            pattern.lastIndex = 0; // Reset global regex state
            if (pattern.test(variant)) {
                return true;
            }
        }
        
        return false;
    }
}

// Default instance for quick access
export const defaultTextNormalizer = new TextNormalizer();