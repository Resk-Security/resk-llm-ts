import { randomUUID } from 'crypto';
import { SecurityFeatureConfig } from "../index";

// Simple prefix for easy detection (could be made more complex)
const CANARY_TOKEN_PREFIX = "ctkn-";

export interface CanaryTokenConfig extends SecurityFeatureConfig {
    // Future options: custom prefix, token format, etc.
}

interface TokenDetails {
    token: string;
    context: Record<string, any>; // Store associated context (user_id, etc.)
    timestamp: number;
}

export class CanaryTokenManager {
    private config: CanaryTokenConfig;
    private activeTokens: Map<string, TokenDetails> = new Map(); // Store generated tokens

    constructor(config?: CanaryTokenConfig) {
        this.config = {
            enabled: true,
            ...(config || {}),
        };
    }

    /**
     * Generates a unique canary token.
     */
    private generateToken(): string {
        return `${CANARY_TOKEN_PREFIX}${randomUUID()}`;
    }

    /**
     * Inserts a canary token into the given text (e.g., a prompt).
     * Adds the token and its context to the active tokens list.
     * @param text The original text.
     * @param context Optional context to associate with the token.
     * @returns The modified text and the generated token, or original text and null if disabled.
     */
    insertToken(text: string, context: Record<string, any> = {}): { modifiedText: string; token: string | null } {
        if (!this.config.enabled) {
            return { modifiedText: text, token: null };
        }

        const token = this.generateToken();
        const tokenDetails: TokenDetails = {
            token,
            context,
            timestamp: Date.now(),
        };
        this.activeTokens.set(token, tokenDetails);

        // Simple insertion strategy: append as a comment or hidden marker.
        // A real implementation might use more subtle methods.
        const modifiedText = `${text}\n<!-- ${token} -->`; // Append as HTML comment
        // Alternative: const modifiedText = `${text} ${token}`; // Simple append

        // console.log(`Inserted canary token: ${token}`);
        return { modifiedText, token };
    }

    /**
     * Checks a given text (e.g., a response) for any known active canary tokens.
     * @param text The text to check.
     * @param associatedTokens Optional list of specific tokens expected in this response.
     * @returns List of found token details.
     */
    check_for_leaks(text: string, associatedTokens?: string[]): TokenDetails[] {
        if (!this.config.enabled || !text) {
            return [];
        }

        const foundTokens: TokenDetails[] = [];
        const tokensToCheck = associatedTokens 
            ? associatedTokens.filter(t => this.activeTokens.has(t))
            : Array.from(this.activeTokens.keys());

        for (const token of tokensToCheck) {
            if (text.includes(token)) {
                const details = this.activeTokens.get(token);
                if (details) {
                    foundTokens.push(details);
                    console.warn(`Canary token leak detected: ${token}, Context: ${JSON.stringify(details.context)}`);
                    // Optionally remove the token from active list once detected
                    // this.activeTokens.delete(token);
                }
            }
        }
        return foundTokens;
    }

    /**
     * Removes an expired or detected token from the active list.
     */
    revokeToken(token: string): boolean {
        return this.activeTokens.delete(token);
    }
}

/**
 * A generic detector that looks for the canary token pattern, 
 * useful if the manager instance isn't available.
 */
export class CanaryTokenDetector {
    private pattern: RegExp;

    constructor(prefix: string = CANARY_TOKEN_PREFIX) {
        // Escape prefix for regex and match UUID pattern
        const escapedPrefix = prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        this.pattern = new RegExp(`${escapedPrefix}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, 'gi');
    }

    /**
     * Detects potential canary tokens in a text.
     * @param text The text to scan.
     * @returns Object indicating if tokens were found and the matches.
     */
    detect(text: string): { canary_tokens_found: boolean; details: string[] } {
        const matches = text.match(this.pattern);
        if (matches && matches.length > 0) {
            return {
                canary_tokens_found: true,
                details: matches,
            };
        }
        return { canary_tokens_found: false, details: [] };
    }
} 