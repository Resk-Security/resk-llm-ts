/**
 * HTML Sanitizer - Uses sanitize-html library for robust HTML cleaning
 * 
 * Features:
 * - Professional-grade HTML sanitization using sanitize-html
 * - Removes dangerous tags, attributes, and protocols
 * - Configurable allowlist of safe elements
 * - Battle-tested against XSS attacks
 * - No regex vulnerabilities (ReDoS-safe)
 */

import sanitizeHtml from 'sanitize-html';
import { SecurityFeatureConfig } from "../index";
import type { ChatCompletionMessageParam } from "openai/resources/chat/completions";

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
        
        // Use sanitize-html for professional-grade HTML sanitization
        // This is much safer than regex-based approaches and prevents ReDoS
        const sanitized = sanitizeHtml(text, {
            // By default, allow no tags (strip all HTML)
            allowedTags: this.config.allowedTags || [],
            // By default, allow no attributes
            allowedAttributes: {},
            // Remove script src, object data, etc.
            disallowedTagsMode: 'discard',
            // Remove dangerous protocols
            allowedSchemes: ['http', 'https', 'mailto'],
            // Keep text content when removing tags
            exclusiveFilter: function(frame) {
                // Remove any remaining dangerous elements
                return frame.tag === 'script' || 
                       frame.tag === 'style' || 
                       frame.tag === 'object' || 
                       frame.tag === 'embed' || 
                       frame.tag === 'iframe';
            }
        });
        
        return sanitized;
    }
} 