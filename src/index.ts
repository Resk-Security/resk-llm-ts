import OpenAI from 'openai';
import { type ChatCompletionCreateParamsNonStreaming, type ChatCompletionMessageParam } from 'openai/resources/chat/completions';
import { PIIProtector, type PIIDetectionConfig, defaultPIIRegex } from './security/pii_protector';
import { InputSanitizer, type InputSanitizationConfig } from './security/sanitizer';
import { PromptInjectionDetector, type PromptInjectionConfig } from './security/prompt_injection';
import { HeuristicFilter, type HeuristicFilterConfig } from './security/heuristic_filter';
import { VectorDatabase, type VectorDBConfig } from './security/vector_db';
import { CanaryTokenManager, type CanaryTokenConfig } from './security/canary_tokens';
import { type EmbeddingFunction, type SimilarityResult } from './types';
import { defaultPiiPatterns } from './security/patterns/pii_patterns'; // Import PII pattern defaults

// --- Configuration Interfaces --- 

// Base config for features that are just enabled/disabled
export interface SecurityFeatureConfig {
    enabled: boolean;
}

// Re-export specific configs from modules
export { PIIDetectionConfig, InputSanitizationConfig, PromptInjectionConfig, HeuristicFilterConfig, VectorDBConfig, CanaryTokenConfig };

// Main configuration combining all features
export interface ReskSecurityConfig {
    inputSanitization?: InputSanitizationConfig;
    piiDetection?: PIIDetectionConfig;
    promptInjection?: PromptInjectionConfig;
    heuristicFilter?: HeuristicFilterConfig;
    vectorDb?: Omit<VectorDBConfig, 'embeddingFunction'>; // Embedding fn managed by client
    canaryTokens?: CanaryTokenConfig;
    contentModeration?: SecurityFeatureConfig; // Placeholder
}

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
        if (this.globalSecurityConfig.vectorDb?.enabled && this.embeddingFn) {
            this.vectorDb = new VectorDatabase({
                ...this.globalSecurityConfig.vectorDb, // Spread specific DB config
                enabled: true, // Ensure enabled is true here
                embeddingFunction: this.embeddingFn, // Provide the function
            });
        } else if (this.globalSecurityConfig.vectorDb?.enabled && !this.embeddingFn) {
            console.warn("Vector DB security feature is enabled, but no embedding function is available. Feature disabled.");
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
            vectorDb: { enabled: true, similarityThreshold: 0.85 }, // Requires embedding fn
            canaryTokens: { enabled: true },
            contentModeration: { enabled: false }, // Placeholder
        };

        // Deep merge would be better for nested objects, but this is okay for now
        const merged: Required<ReskSecurityConfig> = {
             inputSanitization: { ...defaults.inputSanitization, ...providedConfig?.inputSanitization },
             piiDetection: { ...defaults.piiDetection, ...providedConfig?.piiDetection },
             promptInjection: { ...defaults.promptInjection, ...providedConfig?.promptInjection },
             heuristicFilter: { ...defaults.heuristicFilter, ...providedConfig?.heuristicFilter },
             vectorDb: { ...defaults.vectorDb, ...providedConfig?.vectorDb },
             canaryTokens: { ...defaults.canaryTokens, ...providedConfig?.canaryTokens },
             contentModeration: { ...defaults.contentModeration, ...providedConfig?.contentModeration },
        }
        return merged;
    }

    // --- Public API to Add Attack Patterns --- 
    public async addAttackPattern(text: string, metadata: Record<string, any> = {}) {
        if (this.vectorDb?.config.enabled) {
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
        } catch (error: any) { // Catch errors from security checks (e.g., prompt injection)
             console.error("Security Pre-Check Error:", error.message);
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
        delete (openAIParams as any).securityConfig; // Remove our config object
        delete (openAIParams as any)._processedSecurityInfo; // Remove internal prop

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
        let securityInfo: ProcessedSecurityInfo = {};
        let blockReason: string | null = null;

        // --- Apply checks sequentially --- 
        // Order matters: Sanitize first, then detect.

        // 1. Input Sanitization
        if (config.inputSanitization.enabled) {
            currentMessages = currentMessages.map(msg => this.inputSanitizer.sanitizeMessage(msg));
        }
        
        // Process each user message through remaining content checks
        for (const msg of currentMessages) {
             if (typeof msg.content !== 'string' || msg.role !== 'user') {
                 continue; // Only process string content of user messages for now
             }
             const content = msg.content;

             // 2. Heuristic Filter
            if (!blockReason && config.heuristicFilter.enabled) {
                const filterResult = this.heuristicFilter.filter(content);
                if (filterResult.detected) {
                    blockReason = filterResult.reason; // Block immediately
                    break; // Stop further checks on this message
                }
            }

             // 3. Prompt Injection Detection
             if (!blockReason && config.promptInjection.enabled) {
                 const injectionDetected = this.promptInjector.detect(content);
                 if (injectionDetected) {
                     // Configurable action: throw error, log, modify prompt, etc.
                     // For now, we'll set blockReason.
                     blockReason = "Potential prompt injection detected.";
                     break; // Stop further checks on this message
                 }
             }

             // 4. Vector DB Similarity Check
             // Check if vectorDb instance exists (it's only created if enabled and fn exists)
             if (!blockReason && this.vectorDb) { // Check existence of the initialized instance
                const similarityResult = await this.vectorDb.detect(content);
                if (similarityResult.detected) {
                    // Decide action based on similarity (e.g., block vs. flag)
                    blockReason = `High similarity (${similarityResult.max_similarity.toFixed(2)}) to known attack pattern detected.`;
                    securityInfo.similarityResult = similarityResult; // Store for potential logging
                    break; // Stop further checks on this message
                }
            }
        }
        // If blocked during iteration, we might have partially processed messages.
        // It's safer to return the original messages if blocked to avoid sending modified content.
        if (blockReason) {
            return { processedMessages: messages, securityInfo, blockReason };
        }

        // --- Apply modifications after checks --- 

        let finalMessages = currentMessages; // Start with messages potentially sanitized

        // 5. PII Detection (on input - potentially redact *before* sending)
        if (config.piiDetection.enabled) {
            // Pass potentially sanitized messages to PII protector
             finalMessages = finalMessages.map(msg => this.piiProtector.processMessageInput(msg));
        }

        // 6. Canary Token Insertion (applied last to the final prompt string)
        if (config.canaryTokens.enabled) {
             // Find the last message to insert the token into (usually user message)
             // More sophisticated logic might be needed for complex conversations
            let lastMessageIndex = -1;
            for(let i = finalMessages.length - 1; i >= 0; i--) {
                if (typeof finalMessages[i].content === 'string') {
                    lastMessageIndex = i;
                    break;
                }
            }

            if (lastMessageIndex !== -1) {
                const msgToModify = finalMessages[lastMessageIndex];
                const context = { timestamp: Date.now() }; // Add relevant context if needed
                const { modifiedText, token } = this.canaryTokenManager.insertToken(msgToModify.content as string, context);
                
                // Create a new message object to avoid modifying the original array directly
                finalMessages = [
                    ...finalMessages.slice(0, lastMessageIndex),
                    { ...msgToModify, content: modifiedText },
                    ...finalMessages.slice(lastMessageIndex + 1)
                ];
                securityInfo.canaryToken = token;
            } else {
                 console.warn("Could not find suitable message to insert canary token.")
            }
        }
        
        return { processedMessages: finalMessages, securityInfo, blockReason };
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