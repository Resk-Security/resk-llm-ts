// import OpenAI from "openai";
// Use the specific input type from the SDK if available and applicable
// import type { ChatCompletionMessageParam, ChatCompletionContentPartText, ChatCompletionContentPart } from "openai/resources/chat/completions";
import { SecurityFeatureConfig } from "../index";
import type { ChatCompletionMessageParam } from "openai/resources/chat/completions";
// import { ChatCompletionContentPartText, ChatCompletionContentPart } from "openai/resources/chat/completions";
// Removing this import to fix conflict
// import { type InputSanitizationConfig } from "../types";

// Export the config interface
export interface InputSanitizationConfig extends SecurityFeatureConfig {
    // Add properties to fix empty interface error
    sanitizeHtml?: boolean;
    allowedTags?: string[];
}

export class InputSanitizer {
    private config: InputSanitizationConfig;

    constructor(config?: InputSanitizationConfig) {
        this.config = {
            enabled: true,
            ...(config || {}),
        };
    }

    /**
     * Sanitizes the content of a message.
     * Currently focuses on removing HTML tags from string content.
     */
    sanitizeMessage(message: ChatCompletionMessageParam): ChatCompletionMessageParam {
        if (!this.config.enabled) {
            return message;
        }
        
        // Only process string content
        if (typeof message.content === 'string') {
            const processedContent = this.sanitizeText(message.content);
            // Return new object only if content changed
            return message.content === processedContent 
                ? message 
                : { ...message, content: processedContent };
        }
        
        // If content is an array of parts, sanitize text parts (recursive or iterative)
        // This part needs implementation if you expect array content
        // if (Array.isArray(message.content)) {
        //     // ... logic to map over parts and sanitize text parts ...
        // }

        // Return message unchanged if content is null or not string/array
        return message;
    }

    sanitizeText(text: string): string {
        if (!this.config.enabled || !text) {
            return text;
        }
        // Replace entire HTML tag blocks more accurately
        // This handles tags like <script>alert("bad")</script> as a single block
        const htmlBlockRegex = /<[^>]*>[^<]*<\/[^>]*>|<[^>]*\/?>/g;
        const sanitized = text.replace(htmlBlockRegex, '[removed]');
        return sanitized;
    }
} 