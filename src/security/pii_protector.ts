import OpenAI from "openai";
import type { ChatCompletionMessageParam } from "openai/resources/chat/completions";
import { PIIDetectionConfig } from "../index"; // Assuming ReskSecurityConfig is in index.ts
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
            // Reset lastIndex for global regex
            pattern.lastIndex = 0; 
            processedText = processedText.replace(pattern, (match) => `[REDACTED_${this.getPIIType(pattern)}]`);
        }
        return processedText;
    }

    private getPIIType(pattern: RegExp): string {
        // Simple type guessing based on pattern source (improve as needed)
        if (pattern.source.includes('@')) return 'EMAIL';
        if (pattern.source.includes('\d{3}[ -.]?\d{4}')) return 'PHONE'; // Adjusted for new pattern file
        if (pattern.source.includes('\d{4}[ -]?){3}')) return 'CREDIT_CARD';
        if (pattern.source.includes('\.')) return 'IP_ADDRESS'; // Very basic
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
            const processedContent = this.replacePII(message.content);
            return message.content === processedContent 
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

        if (originalContent === redactedContent) {
             return completion; // No changes needed
        }

        // Create a deep copy only if changes were made
        const newCompletion = JSON.parse(JSON.stringify(completion)); 
        newCompletion.choices[0].message.content = redactedContent;
        
        return newCompletion;
    }
} 