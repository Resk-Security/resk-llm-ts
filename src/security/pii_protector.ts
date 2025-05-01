import OpenAI from "openai";
import type { ChatCompletionMessageParam } from "openai/resources/chat/completions";
// Import config type from types.ts
import { type PIIDetectionConfig } from "../types"; 
import { defaultPiiPatterns } from "./patterns/pii_patterns"; // Import from patterns file

// Basic regex patterns for common PII defined in patterns/pii_patterns.ts
// IMPORTANT: These are examples and may not be comprehensive or perfectly accurate.
// Real-world PII detection often requires more sophisticated methods.
export { defaultPiiPatterns }; // Re-export for potential external use

export class PIIProtector {
    private config: PIIDetectionConfig;

    constructor(config?: PIIDetectionConfig) {
        this.config = {
            enabled: true,
            redact: false,
            // Use imported patterns as default
            patterns: defaultPiiPatterns,
            ...(config || {}),
        };
    }

    private replacePII(text: string): string {
        let processedText = text;
        for (const pattern of this.config.patterns || []) {
            // Need to create a fresh copy of the regex to ensure proper global replacement
            // The lastIndex property resets after match, causing subsequent calls to skip matches
            const freshPattern = new RegExp(pattern.source, pattern.flags);
            processedText = processedText.replace(freshPattern, (_match) => `[REDACTED_${this.getPIIType(pattern)}]`);
        }
        return processedText;
    }

    private getPIIType(pattern: RegExp): string {
        // Simple type guessing based on pattern source (improve as needed)
        const source = pattern.source;
        if (source.includes('@')) return 'EMAIL';
        if (source.includes('\\d{3}[)]?[ -.]?\\d{3}')) return 'PHONE';
        if (source.includes('\\d{4}[ -]?){3}')) return 'CREDIT_CARD';
        if (source.includes('25[0-5]|2[0-4][0-9]')) return 'IP_ADDRESS';
        return 'PII';
    }

    /**
     * Processes incoming messages BEFORE sending to LLM.
     * Only processes/redacts messages where content is a string.
     */
    processMessageInput(message: ChatCompletionMessageParam): ChatCompletionMessageParam {
        if (!this.config.enabled || !this.config.redact) {
            return message; // Only process if enabled and redaction is on for input
        }
        
        // Only process string content
        if (typeof message.content === 'string') {
            const originalContent = message.content;
            const processedContent = this.replacePII(originalContent);
            
            // For debugging
            if (originalContent !== processedContent) {
                console.log(`PII detected and redacted: 
                  Original: ${originalContent}
                  Redacted: ${processedContent}`);
            }
            
            return originalContent === processedContent 
                ? message 
                : { ...message, content: processedContent };
        }

        // Return array content or null content unchanged
        return message;
    }

    /**
     * Processes outgoing completion FROM LLM to redact PII.
     */
    processCompletionOutput(completion: OpenAI.Chat.Completions.ChatCompletion): OpenAI.Chat.Completions.ChatCompletion {
        if (!this.config.enabled || !this.config.redact || !completion.choices[0]?.message?.content) {
             return completion;
        }

        const originalContent = completion.choices[0].message.content;
        const redactedContent = this.replacePII(originalContent);

        // For debugging
        if (originalContent !== redactedContent) {
            console.log(`PII detected in output and redacted: 
              Original: ${originalContent}
              Redacted: ${redactedContent}`);
        }

        if (originalContent === redactedContent) {
             return completion; // No changes needed
        }

        // Modify the content directly on the original object for simplicity in this context
        // WARNING: This mutates the input object. If that's undesirable, 
        // a more robust deep copy mechanism is needed.
        completion.choices[0].message.content = redactedContent;
        
        return completion;
    }
} 