import OpenAI from "openai";
// Use the specific input type from the SDK if available and applicable
import type { ChatCompletionMessageParam, ChatCompletionContentPartText, ChatCompletionContentPart } from "openai/resources/chat/completions";
import { SecurityFeatureConfig } from "../index";

// Export the config interface
export interface InputSanitizationConfig extends SecurityFeatureConfig {
    // Add specific sanitization options here if needed later
}

export class InputSanitizer {
    private config: InputSanitizationConfig;

    constructor(config?: InputSanitizationConfig) {
        this.config = {
            enabled: true,
            ...(config || {}),
        };
    }

    // Basic sanitizer: remove potentially harmful script tags or common injection patterns.
    // This is a very basic example and should be expanded based on requirements.
    sanitize(text: string): string {
        if (!this.config.enabled || !text) return text; // Check if enabled
        // Remove script tags
        let sanitized = text.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[removed]');
        // Add more sanitization rules as needed
        // e.g., simple check for common prompt injection phrases
        // sanitized = sanitized.replace(/ignore previous instructions/gi, '[instruction conflict]');
        return sanitized;
    }

    /**
     * Sanitizes the content of a message IF the content is a string.
     * Messages with array content (multi-modal) are returned unchanged 
     * due to complexities in SDK type compatibility after modification.
     */
    sanitizeMessage(message: ChatCompletionMessageParam): ChatCompletionMessageParam {
        if (!this.config.enabled) {
            return message;
        }

        // Only sanitize if content is currently a string
        if (typeof message.content === 'string') {
            const sanitizedContent = this.sanitize(message.content);
            // Return new message object only if content changed
            return message.content === sanitizedContent 
                ? message 
                : { ...message, content: sanitizedContent };
        }
        
        // Return all other message types (null content, array content) unchanged
        return message;
    }
} 