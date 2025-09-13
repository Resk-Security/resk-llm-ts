/**
 * Patterns to detect common special tokens used by LLMs.
 * These patterns help identify token manipulation attempts and model-specific injections.
 */

// Core GPT/OpenAI tokens
export const gptTokenPatterns: RegExp[] = [
    /<\|endoftext\|>/gi,
    /<\|startoftext\|>/gi,
    /<\|fim_prefix\|>/gi,      // Fill-in-the-middle prefix
    /<\|fim_middle\|>/gi,      // Fill-in-the-middle middle
    /<\|fim_suffix\|>/gi,      // Fill-in-the-middle suffix
    /<\|pad\|>/gi,             // Padding token
];

// ChatML (Chat Markup Language) tokens
export const chatmlTokenPatterns: RegExp[] = [
    /<\|im_start\|>/gi,
    /<\|im_end\|>/gi,
    /<\|im_sep\|>/gi,          // Separator token
];

// Llama/Mistral tokens
export const llamaTokenPatterns: RegExp[] = [
    /<s>/gi,                   // Beginning of sequence
    /<\/s>/gi,                 // End of sequence
    /\[INST\]/gi,             // Instruction start
    /\[\/INST\]/gi,           // Instruction end
    /<<SYS>>/gi,              // System message start
    /<\/SYS>>/gi,             // System message end
    /\[BOS\]/gi,              // Beginning of sequence (alternative)
    /\[EOS\]/gi,              // End of sequence (alternative)
    /\[UNK\]/gi,              // Unknown token
    /\[PAD\]/gi,              // Padding token
    /\[MASK\]/gi,             // Mask token
];

// Anthropic Claude tokens
export const claudeTokenPatterns: RegExp[] = [
    /\|ASSISTANT\|/gi,
    /\|HUMAN\|/gi,
    /\|SYSTEM\|/gi,
    /<claude>/gi,
    /<\/claude>/gi,
];

// Cohere tokens
export const cohereTokenPatterns: RegExp[] = [
    /<\|START_OF_TURN_TOKEN\|>/gi,
    /<\|END_OF_TURN_TOKEN\|>/gi,
    /<\|CHATBOT_TOKEN\|>/gi,
    /<\|USER_TOKEN\|>/gi,
    /<\|SYSTEM_TOKEN\|>/gi,
];

// Google Bard/Gemini tokens
export const geminiTokenPatterns: RegExp[] = [
    /<start_of_turn>/gi,
    /<end_of_turn>/gi,
    /<start_of_image>/gi,
    /<end_of_image>/gi,
];

// General/Universal special tokens
export const universalTokenPatterns: RegExp[] = [
    /\[CLS\]/gi,              // Classification token (BERT-style)
    /\[SEP\]/gi,              // Separator token (BERT-style)
    /\[PAD\]/gi,              // Padding token
    /\[UNK\]/gi,              // Unknown token
    /\[MASK\]/gi,             // Mask token
    /<unk>/gi,                // Unknown token (alternative)
    /<pad>/gi,                // Padding token (alternative)
    /<mask>/gi,               // Mask token (alternative)
    /<sep>/gi,                // Separator token (alternative)
    /<cls>/gi,                // Classification token (alternative)
];

// Dangerous token injection patterns
export const dangerousTokenPatterns: RegExp[] = [
    // Attempts to inject system-level tokens
    /<\|system\|>/gi,
    /<\|admin\|>/gi,
    /<\|root\|>/gi,
    /<\|sudo\|>/gi,
    
    // Token boundary manipulation
    // eslint-disable-next-line no-control-regex
    /\x00/g,                  // Null bytes
    /\uffff/g,                // Unicode max character
    // eslint-disable-next-line no-control-regex
    /\u0001/g,                // Start of heading
    // eslint-disable-next-line no-control-regex
    /\u0002/g,                // Start of text
    // eslint-disable-next-line no-control-regex
    /\u0003/g,                // End of text
    
    // Model-specific bypass attempts
    /<\|.*?\|>/gi,            // Generic special token format
    /\[.*?\]/g,               // Generic bracket format (be careful with this one)
    
    // Encoding-based token injection
    /&#x[0-9a-f]+;/gi,        // Hex HTML entities
    /&#\d+;/gi,               // Decimal HTML entities
    /%[0-9a-f]{2}/gi,         // URL encoding
    /\\u[0-9a-f]{4}/gi,       // Unicode escape sequences
    /\\x[0-9a-f]{2}/gi,       // Hex escape sequences
];

// Combined pattern for comprehensive detection
export const defaultSpecialTokenPatterns: RegExp[] = [
    ...gptTokenPatterns,
    ...chatmlTokenPatterns,
    ...llamaTokenPatterns,
    ...claudeTokenPatterns,
    ...cohereTokenPatterns,
    ...geminiTokenPatterns,
    ...universalTokenPatterns,
    ...dangerousTokenPatterns,
];

/**
 * Token detection utility class
 */
export class SpecialTokenDetector {
    private patterns: RegExp[];
    
    constructor(customPatterns: RegExp[] = []) {
        this.patterns = [...defaultSpecialTokenPatterns, ...customPatterns];
    }
    
    /**
     * Detect special tokens in text
     */
    detect(text: string): {
        detected: boolean;
        tokens: string[];
        patterns: RegExp[];
        positions: Array<{token: string, position: number, pattern: RegExp}>;
    } {
        const result = {
            detected: false,
            tokens: [] as string[],
            patterns: [] as RegExp[],
            positions: [] as Array<{token: string, position: number, pattern: RegExp}>
        };
        
        for (const pattern of this.patterns) {
            pattern.lastIndex = 0; // Reset regex state
            let match;
            
            while ((match = pattern.exec(text)) !== null) {
                result.detected = true;
                const token = match[0];
                
                if (!result.tokens.includes(token)) {
                    result.tokens.push(token);
                }
                
                if (!result.patterns.includes(pattern)) {
                    result.patterns.push(pattern);
                }
                
                result.positions.push({
                    token: token,
                    position: match.index,
                    pattern: pattern
                });
                
                // Prevent infinite loops with global regexes
                if (pattern.global && match.index === pattern.lastIndex) {
                    break;
                }
            }
        }
        
        return result;
    }
    
    /**
     * Check if text contains dangerous token patterns
     */
    containsDangerousTokens(text: string): boolean {
        for (const pattern of dangerousTokenPatterns) {
            pattern.lastIndex = 0;
            if (pattern.test(text)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Sanitize text by removing detected special tokens
     */
    sanitize(text: string, replacement: string = '[TOKEN_REMOVED]'): {
        sanitizedText: string;
        removedTokens: string[];
    } {
        let sanitizedText = text;
        const removedTokens: string[] = [];
        
        for (const pattern of this.patterns) {
            pattern.lastIndex = 0;
            const matches = text.match(pattern);
            
            if (matches) {
                removedTokens.push(...matches);
                sanitizedText = sanitizedText.replace(pattern, replacement);
            }
        }
        
        return {
            sanitizedText,
            removedTokens: [...new Set(removedTokens)] // Remove duplicates
        };
    }
    
    /**
     * Add custom patterns
     */
    addPattern(pattern: RegExp): void {
        this.patterns.push(pattern);
    }
    
    /**
     * Get statistics about patterns
     */
    getStats(): {
        totalPatterns: number;
        patternsByCategory: Record<string, number>;
    } {
        return {
            totalPatterns: this.patterns.length,
            patternsByCategory: {
                gpt: gptTokenPatterns.length,
                chatML: chatmlTokenPatterns.length,
                llama: llamaTokenPatterns.length,
                claude: claudeTokenPatterns.length,
                cohere: cohereTokenPatterns.length,
                gemini: geminiTokenPatterns.length,
                universal: universalTokenPatterns.length,
                dangerous: dangerousTokenPatterns.length
            }
        };
    }
}

// Default detector instance
export const defaultTokenDetector = new SpecialTokenDetector(); 