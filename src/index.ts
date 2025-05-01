import OpenAI from 'openai';
import { type ChatCompletionCreateParamsNonStreaming, type ChatCompletionMessageParam } from 'openai/resources/chat/completions';
// Import config types from types.ts
import {
    type ReskSecurityConfig,
    type EmbeddingFunction,
    type SimilarityResult,
    type PIIDetectionConfig,
    type InputSanitizationConfig,
    type PromptInjectionConfig,
    type HeuristicFilterConfig,
    type VectorDBConfig,
    type CanaryTokenConfig,
    type SecurityFeatureConfig
} from './types';
import { PIIProtector } from './security/pii_protector';
import { InputSanitizer } from './security/sanitizer';
import { PromptInjectionDetector } from './security/prompt_injection';
import { HeuristicFilter } from './security/heuristic_filter';
import { VectorDatabase } from './security/vector_db';
import { CanaryTokenManager } from './security/canary_tokens';
import { defaultPiiPatterns } from './security/patterns/pii_patterns'; // Import PII pattern defaults

// --- Configuration Interfaces are now in types.ts ---

// Re-export specific configs from types.ts (optional, but can be convenient)
export { PIIDetectionConfig, InputSanitizationConfig, PromptInjectionConfig, HeuristicFilterConfig, VectorDBConfig, CanaryTokenConfig, SecurityFeatureConfig, ReskSecurityConfig };

// --- Helper Function for OpenAI Embeddings --- 

/**
 * Creates an embedding function using the provided OpenAI client.
 */
function createOpenAIEmbeddingFunction(client: OpenAI, model: string = "text-embedding-3-small"): EmbeddingFunction {
    return async (text: string): Promise<number[]> => {
        try {
            const response = await client.embeddings.create({
                input: text,
                model: model,
            });
            return response.data[0].embedding;
        } catch (error) {
            console.error("Error getting OpenAI embedding:", error);
            throw new Error("Failed to generate embedding."); // Re-throw for handling
        }
    };
}

// --- Augmented Request Type & Main Client --- 

// Add security processing results to the request parameters temporarily
type ProcessedSecurityInfo = {
    canaryToken?: string | null;
    similarityResult?: SimilarityResult;
}

// Augment OpenAI's request type
export type ReskChatCompletionCreateParams = Omit<ChatCompletionCreateParamsNonStreaming, 'messages'> & {
    messages: ChatCompletionMessageParam[]; // Ensure messages is always present and correctly typed
    securityConfig?: ReskSecurityConfig;
    // Internal property to pass security results
    _processedSecurityInfo?: ProcessedSecurityInfo;
};


export class ReskLLMClient {
    private openai: OpenAI;
    private globalSecurityConfig: ReskSecurityConfig;
    private embeddingFn: EmbeddingFunction | null = null;

    // Security Module Instances
    private inputSanitizer: InputSanitizer;
    private piiProtector: PIIProtector;
    private promptInjector: PromptInjectionDetector;
    private heuristicFilter: HeuristicFilter;
    private vectorDb: VectorDatabase | null = null;
    private canaryTokenManager: CanaryTokenManager;

    constructor(options: {
        openRouterApiKey?: string;
        openRouterBaseUrl?: string;
        openaiClient?: OpenAI; // Allow passing an existing client
        securityConfig?: ReskSecurityConfig;
        embeddingFunction?: EmbeddingFunction; // Allow custom embedding function
        embeddingModel?: string; // Specify embedding model if using OpenAI
    }) {
        if (options.openaiClient) {
            this.openai = options.openaiClient;
        } else {
            const apiKey = options.openRouterApiKey || process.env.OPENROUTER_API_KEY;
            if (!apiKey) {
                throw new Error('OpenRouter API key or OpenAI client instance is required.');
            }
            this.openai = new OpenAI({
                apiKey: apiKey,
                baseURL: options.openRouterBaseUrl || 'https://openrouter.ai/api/v1',
            });
        }

        // --- Initialize Embedding Function --- 
        if (options.embeddingFunction) {
            this.embeddingFn = options.embeddingFunction;
        } else {
            // Default to OpenAI embeddings if client is available
            this.embeddingFn = createOpenAIEmbeddingFunction(this.openai, options.embeddingModel);
        }

        // --- Initialize Security Modules --- 
        // Define default global security settings, merging with user-provided config
        this.globalSecurityConfig = this.mergeSecurityConfigs(options.securityConfig);

        this.inputSanitizer = new InputSanitizer(this.globalSecurityConfig.inputSanitization);
        this.piiProtector = new PIIProtector(this.globalSecurityConfig.piiDetection);
        this.promptInjector = new PromptInjectionDetector(this.globalSecurityConfig.promptInjection);
        this.heuristicFilter = new HeuristicFilter(this.globalSecurityConfig.heuristicFilter);
        this.canaryTokenManager = new CanaryTokenManager(this.globalSecurityConfig.canaryTokens);

        // Initialize Vector DB only if enabled and embedding function is available
        // NOTE: VectorDBConfig in types.ts includes embeddingFunction, but ReskSecurityConfig omits it
        // We re-add it here when constructing VectorDatabase
        const vectorDbUserConfig = this.globalSecurityConfig.vectorDb;
        if (vectorDbUserConfig?.enabled && this.embeddingFn) {
            this.vectorDb = new VectorDatabase({
                ...vectorDbUserConfig,
                enabled: true, // Ensure enabled is explicitly true
                embeddingFunction: this.embeddingFn, // Provide the function
            });
        } else if (vectorDbUserConfig?.enabled && !this.embeddingFn) {
            console.warn("Vector DB security feature is enabled, but no embedding function is available. Feature disabled.");
            // Ensure the effective global config reflects this disablement
            if(this.globalSecurityConfig.vectorDb) this.globalSecurityConfig.vectorDb.enabled = false;
        }
    }

    /** Helper to merge default and provided security configs */
    private mergeSecurityConfigs(providedConfig?: ReskSecurityConfig): Required<ReskSecurityConfig> {
         const defaults: Required<ReskSecurityConfig> = {
            inputSanitization: { enabled: true },
            piiDetection: { enabled: true, redact: false, patterns: defaultPiiPatterns },
            promptInjection: { enabled: true, level: 'basic' },
            heuristicFilter: { enabled: true },
            // Default VectorDB config (embedding function added later if needed)
            vectorDb: { enabled: true, similarityThreshold: 0.85 }, 
            canaryTokens: { enabled: true },
            contentModeration: { enabled: false }, // Placeholder
        };

        // Deep merge would be better for nested objects, but this is okay for now
        const merged: Required<ReskSecurityConfig> = {
             inputSanitization: { ...defaults.inputSanitization, ...providedConfig?.inputSanitization },
             // Ensure patterns aren't accidentally overwritten with undefined if user provides {} for piiDetection
             piiDetection: { 
                 ...defaults.piiDetection, 
                 ...(providedConfig?.piiDetection || {}), 
                 patterns: providedConfig?.piiDetection?.patterns ?? defaults.piiDetection.patterns
             },
             promptInjection: { ...defaults.promptInjection, ...providedConfig?.promptInjection },
             heuristicFilter: { ...defaults.heuristicFilter, ...providedConfig?.heuristicFilter },
             // Merge vectorDb config carefully
             vectorDb: { ...defaults.vectorDb, ...(providedConfig?.vectorDb || {}) },
             canaryTokens: { ...defaults.canaryTokens, ...providedConfig?.canaryTokens },
             contentModeration: { ...defaults.contentModeration, ...providedConfig?.contentModeration },
        }
        return merged;
    }

    // --- Public API to Add Attack Patterns --- 
    public async addAttackPattern(text: string, metadata: Record<string, unknown> = {}) {
        // Use the new isEnabled() method
        if (this.vectorDb?.isEnabled()) {
           await this.vectorDb.addTextEntry(text, metadata);
           console.info(`Added attack pattern to Vector DB: ${text.substring(0, 50)}...`);
        } else {
             console.warn("Cannot add attack pattern: Vector DB is disabled or not initialized.")
        }
    }

    // --- Core Chat Completion Method --- 
    public async chatCompletion(params: ReskChatCompletionCreateParams): Promise<OpenAI.Chat.Completions.ChatCompletion> {
        
        // 1. Merge global config with request-specific config
        const requestConfig = this.mergeSecurityConfigs(params.securityConfig);

        // 2. Apply security checks PRE-API Call
        let processedMessages = params.messages;
        let securityInfo: ProcessedSecurityInfo = {};
        let blockReason: string | null = null;

        try {
             const preCheckResult = await this.applyPreSecurityChecks(processedMessages, requestConfig);
             processedMessages = preCheckResult.processedMessages;
             securityInfo = preCheckResult.securityInfo;
             blockReason = preCheckResult.blockReason;
        } catch (error: unknown) { // Use unknown instead of any
             console.error("Security Pre-Check Error:", error instanceof Error ? error.message : String(error));
             throw error; // Re-throw the error to halt processing
        }

        // If a check determined we should block, throw an error now
        if (blockReason) {
            throw new Error(`Request blocked by security policy: ${blockReason}`);
        }

        // 3. Prepare params for OpenAI, removing our custom config
        const openAIParams: ChatCompletionCreateParamsNonStreaming = {
            ...params,
            messages: processedMessages,
        };
        
        // A safer way to delete custom properties
        const customOpenAIParams = openAIParams as Partial<ReskChatCompletionCreateParams>;
        delete customOpenAIParams.securityConfig;
        delete customOpenAIParams._processedSecurityInfo;

        // 4. Call OpenRouter API
        const completion = await this.openai.chat.completions.create(openAIParams);

        // 5. Apply security checks POST-API Call
        const finalCompletion = this.applyPostSecurityChecks(completion, requestConfig, securityInfo);

        return finalCompletion;
    }

    // Expose the chat completions API under a similar structure to OpenAI's SDK
    public get chat() {
        return {
            completions: {
                create: this.chatCompletion.bind(this),
            },
        };
    }

    // --- Security Check Application --- 

    private async applyPreSecurityChecks(
        messages: OpenAI.Chat.ChatCompletionMessageParam[], 
        config: Required<ReskSecurityConfig>
    ): Promise<{ 
        processedMessages: OpenAI.Chat.ChatCompletionMessageParam[]; 
        securityInfo: ProcessedSecurityInfo; 
        blockReason: string | null; 
    }> {
        let currentMessages = messages;
        const securityInfo: ProcessedSecurityInfo = {};
        let blockReason: string | null = null;

        // --- Apply checks sequentially --- 
        // Order matters: Sanitize first, then detect.

        // 1. Input Sanitization
        if (config.inputSanitization.enabled) {
            currentMessages = currentMessages.map(msg => this.inputSanitizer.sanitizeMessage(msg));
        }
        
        // Process each user message through remaining content checks
        for (let i = 0; i < currentMessages.length; i++) {
            const msg = currentMessages[i];
             if (typeof msg.content !== 'string' || msg.role !== 'user') {
                 continue; // Only process string content of user messages for now
             }
             const content = msg.content;

            // 2. Heuristic Filter
            if (config.heuristicFilter.enabled) {
                const heuristicResult = this.heuristicFilter.filter(content);
                if (heuristicResult.detected) {
                    blockReason = heuristicResult.reason || "Blocked by heuristic filter";
                    break; // Block immediately
                }
            }

            // 3. Prompt Injection (Basic)
            if (config.promptInjection.enabled && config.promptInjection.level === 'basic') {
                if (this.promptInjector.detect(content)) {
                    blockReason = "Potential prompt injection detected.";
                    break; // Block immediately
                }
            }
            
            // 4. Vector DB Check (if enabled and initialized)
            // Use isEnabled() here too
            if (this.vectorDb?.isEnabled()) { 
                const similarityResult = await this.vectorDb.detect(content);
                securityInfo.similarityResult = similarityResult; // Store result
                if (similarityResult.detected) {
                     blockReason = `High similarity (${similarityResult.max_similarity.toFixed(2)}) to known attack pattern detected.`;
                    break; // Block immediately
                }
            }

            // 5. PII Detection (Redaction happens separately if enabled)
            if (config.piiDetection.enabled && config.piiDetection.redact) {
                const processedMsg = this.piiProtector.processMessageInput(msg);
                // Important: Update the message in the array if it changed
                if (processedMsg !== msg) {
                    currentMessages[i] = processedMsg;
                }
            }

            // 6. Canary Token Insertion
            if (config.canaryTokens.enabled) {
                 // Ensure msg.content is still a string after PII redaction
                 if(typeof currentMessages[i].content === 'string') { 
                     const { modifiedText, token } = this.canaryTokenManager.insertToken(currentMessages[i].content as string);
                     // Important: Update the message in the array
                     currentMessages[i] = { ...currentMessages[i], content: modifiedText };
                     securityInfo.canaryToken = token; // Store the token for post-check
                 }
            }
        }
        
        // Return results if no blocking occurred
        return { processedMessages: currentMessages, securityInfo, blockReason };
    }

    private applyPostSecurityChecks(
        completion: OpenAI.Chat.Completions.ChatCompletion, 
        config: Required<ReskSecurityConfig>, 
        securityInfo: ProcessedSecurityInfo
    ): OpenAI.Chat.Completions.ChatCompletion {
        let processedCompletion = completion;
        const responseContent = completion.choices[0]?.message?.content;

        if (!responseContent) {
            return processedCompletion; // No content to check
        }

        // 1. Canary Token Leak Detection
        if (config.canaryTokens.enabled && securityInfo.canaryToken) {
            this.canaryTokenManager.check_for_leaks(responseContent, [securityInfo.canaryToken]);
            // Action on leak detected? Log, alert, modify response? TBD.
            // If a leak is critical, you might modify the response:
            // if (leaks.length > 0) { processedCompletion = ... // Modify completion }
        }

        // 2. Content Moderation (Placeholder)
        if (config.contentModeration.enabled) {
            console.warn('Content Moderation is not yet implemented.');
            // Placeholder: Check responseContent for harmful content
        }

        // 3. PII Detection (on output - redact if configured)
        if (config.piiDetection.enabled && config.piiDetection.redact) {
            // Pass potentially moderated completion to PII protector
            processedCompletion = this.piiProtector.processCompletionOutput(processedCompletion);
        }
        
        return processedCompletion;
    }
} 