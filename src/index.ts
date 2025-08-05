import OpenAI from 'openai';
import { type ChatCompletionCreateParamsNonStreaming, type ChatCompletionMessageParam } from 'openai/resources/chat/completions';
import { LLMProvider, ProviderFactory, LLMCompletionRequest, LLMProviderConfig } from './providers/llm_provider';
// Import config types from types.ts
import {
    SecurityException,
    type ReskSecurityConfig,
    type EmbeddingFunction,
    type SimilarityResult,
    type PIIDetectionConfig,
    type InputSanitizationConfig,
    type PromptInjectionConfig,
    type HeuristicFilterConfig,
    type VectorDBConfig,
    type CanaryTokenConfig,
    type ContentModerationConfig,
    type SecurityFeatureConfig,
    type IVectorDatabase
} from './types';
import { PIIProtector } from './security/pii_protector';
import { InputSanitizer } from './security/sanitizer';
import { PromptInjectionDetector } from './security/prompt_injection';
import { HeuristicFilter } from './security/heuristic_filter';
import { VectorDatabase } from './security/vector_db';
import { CanaryTokenManager } from './security/canary_tokens';
import { ContentModerator } from './security/content_moderation';
import { defaultPiiPatterns } from './security/patterns/pii_patterns'; // Import PII pattern defaults

// --- Configuration Interfaces are now in types.ts ---

// Re-export specific configs from types.ts (optional, but can be convenient)
export { SecurityException, PIIDetectionConfig, InputSanitizationConfig, PromptInjectionConfig, HeuristicFilterConfig, VectorDBConfig, CanaryTokenConfig, ContentModerationConfig, SecurityFeatureConfig, ReskSecurityConfig };

// Re-export additional security interfaces
export { CustomHeuristicRule, HeuristicFilterResult } from './security/heuristic_filter';
export { InjectionDetectionResult } from './security/prompt_injection';
export { ModerationResult } from './security/content_moderation';
export { AlertConfig, AlertPayload, AlertResult } from './security/alert_system';

// Re-export frontend security components
export { ReskSecurityFilter, FrontendSecurityConfig, SecurityValidationResult, ProviderType, ProviderMessage, ProviderRequest, ProviderResponse } from './frontend/resk_security_filter';
export { SecurityCache, CacheConfig } from './frontend/security_cache';
export { PerformanceOptimizer, PerformanceConfig, PerformanceMetrics } from './frontend/performance_optimizer';
export { SIEMIntegration, SIEMConfig, SecurityEvent, SIEMMetrics } from './frontend/siem_integration';

// --- Helper Function for OpenAI Embeddings ---

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
    private llmProvider: LLMProvider;
    private globalSecurityConfig: ReskSecurityConfig;
    private embeddingFn: EmbeddingFunction | null = null;

    // Security Module Instances
    private inputSanitizer: InputSanitizer;
    private piiProtector: PIIProtector;
    private promptInjector: PromptInjectionDetector;
    private heuristicFilter: HeuristicFilter;
    private vectorDb: IVectorDatabase | null = null; // Peut être custom ou interne
    private canaryTokenManager: CanaryTokenManager;
    private contentModerator: ContentModerator;

    constructor(options: {
        // Legacy OpenAI/OpenRouter support
        openRouterApiKey?: string;
        openRouterBaseUrl?: string;
        openaiClient?: OpenAI; // Allow passing an existing client
        
        // New multi-provider support
        provider?: 'openai' | 'anthropic' | 'cohere' | 'huggingface';
        providerConfig?: LLMProviderConfig;
        llmProvider?: LLMProvider; // Allow direct provider injection
        
        // Security configuration
        securityConfig?: ReskSecurityConfig;
        embeddingFunction?: EmbeddingFunction; // Allow custom embedding function
        embeddingModel?: string; // Specify embedding model if using OpenAI
        vectorDbInstance?: IVectorDatabase; // Permettre l'injection d'une DB custom
    }) {
        // --- Initialize LLM Provider ---
        if (options.llmProvider) {
            // Direct provider injection
            this.llmProvider = options.llmProvider;
        } else if (options.provider && options.providerConfig) {
            // Multi-provider initialization
            this.llmProvider = ProviderFactory.createProvider(
                options.provider, 
                options.providerConfig,
                options.openaiClient
            );
        } else {
            // Legacy OpenAI/OpenRouter initialization (backward compatibility)
            let openaiClient: OpenAI;
            
            if (options.openaiClient) {
                openaiClient = options.openaiClient;
            } else {
                const apiKey = options.openRouterApiKey || process.env.OPENROUTER_API_KEY;
                if (!apiKey) {
                    throw new Error('OpenRouter API key or OpenAI client instance is required.');
                }
                openaiClient = new OpenAI({
                    apiKey: apiKey,
                    baseURL: options.openRouterBaseUrl || 'https://openrouter.ai/api/v1',
                });
            }
            
            // Create OpenAI provider
            this.llmProvider = ProviderFactory.createProvider('openai', {
                apiKey: openaiClient.apiKey || '',
                baseUrl: openaiClient.baseURL
            }, openaiClient);
        }

        // --- Initialize Embedding Function --- 
        if (options.embeddingFunction) {
            this.embeddingFn = options.embeddingFunction;
        } else if (this.llmProvider.generateEmbedding) {
            // Use provider's embedding function if available
            this.embeddingFn = async (text: string): Promise<number[]> => {
                try {
                    return await this.llmProvider.generateEmbedding!(text, options.embeddingModel);
                } catch (error) {
                    console.error(`Error getting embedding from ${this.llmProvider.getProviderName()}:`, error);
                    throw new Error("Failed to generate embedding.");
                }
            };
        } else {
            console.warn(`Provider ${this.llmProvider.getProviderName()} does not support embeddings. Vector DB features will be disabled.`);
            this.embeddingFn = null;
        }

        // --- Initialize Security Modules --- 
        // Define default global security settings, merging with user-provided config
        this.globalSecurityConfig = this.mergeSecurityConfigs(options.securityConfig);

        this.inputSanitizer = new InputSanitizer(this.globalSecurityConfig.inputSanitization);
        this.piiProtector = new PIIProtector(this.globalSecurityConfig.piiDetection);
        this.promptInjector = new PromptInjectionDetector(this.globalSecurityConfig.promptInjection);
        this.heuristicFilter = new HeuristicFilter(this.globalSecurityConfig.heuristicFilter);
        this.canaryTokenManager = new CanaryTokenManager(this.globalSecurityConfig.canaryTokens);
        this.contentModerator = new ContentModerator(this.globalSecurityConfig.contentModeration);

        // --- Vector DB: priorité à l'instance custom fournie ---
        if (options.vectorDbInstance) {
            this.vectorDb = options.vectorDbInstance;
        } else {
            // Initialize Vector DB only if enabled and embedding function is available
            const vectorDbUserConfig = this.globalSecurityConfig.vectorDb;
            if (vectorDbUserConfig?.enabled && this.embeddingFn) {
                this.vectorDb = new VectorDatabase({
                    ...vectorDbUserConfig,
                    enabled: true, // Ensure enabled is explicitly true
                    embeddingFunction: this.embeddingFn, // Provide the function
                });
            } else if (vectorDbUserConfig?.enabled && !this.embeddingFn) {
                console.warn("Vector DB security feature is enabled, but no embedding function is available. Feature disabled.");
                if(this.globalSecurityConfig.vectorDb) this.globalSecurityConfig.vectorDb.enabled = false;
            }
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
            contentModeration: { 
                enabled: true, 
                severity: 'medium',
                actions: {
                    toxic: 'block',
                    adult: 'warn',
                    violence: 'block',
                    selfHarm: 'block',
                    misinformation: 'warn'
                },
                customPatterns: [],
                languageSupport: ['en', 'fr'],
                contextAware: true
            },
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

        // 3. Prepare params for LLM Provider, removing our custom config
        const llmRequest: LLMCompletionRequest = {
            model: params.model,
            messages: processedMessages.map(msg => ({
                role: msg.role as 'system' | 'user' | 'assistant',
                content: typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content),
                ...((msg as any).name && { name: (msg as any).name })
            })),
            max_tokens: params.max_tokens || undefined,
            temperature: params.temperature || undefined,
            top_p: params.top_p || undefined,
            frequency_penalty: params.frequency_penalty || undefined,
            presence_penalty: params.presence_penalty || undefined,
            stop: params.stop || undefined,
            stream: false, // Security system doesn't support streaming yet
        };

        // 4. Call LLM Provider API
        const completion = await this.llmProvider.chatCompletion(llmRequest);
        
        // Convert back to OpenAI format for compatibility
        const openAICompatibleCompletion: OpenAI.Chat.Completions.ChatCompletion = {
            id: completion.id,
            object: 'chat.completion' as const,
            created: completion.created,
            model: completion.model,
            choices: completion.choices.map(choice => ({
                index: choice.index,
                message: {
                    role: choice.message.role,
                    content: choice.message.content,
                    ...((choice.message as any).function_call && { function_call: (choice.message as any).function_call }),
                    ...((choice.message as any).tool_calls && { tool_calls: (choice.message as any).tool_calls })
                },
                logprobs: null,
                finish_reason: choice.finish_reason as any
            })),
            usage: completion.usage ? {
                prompt_tokens: completion.usage.prompt_tokens,
                completion_tokens: completion.usage.completion_tokens,
                total_tokens: completion.usage.total_tokens
            } : undefined
        };

        // 5. Apply security checks POST-API Call
        const finalCompletion = await this.applyPostSecurityChecks(openAICompatibleCompletion, requestConfig, securityInfo);

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

            // 2. Heuristic Filter with Custom Rules
            if (config.heuristicFilter.enabled) {
                const heuristicResult = this.heuristicFilter.filter(content, { role: msg.role });
                if (heuristicResult.detected) {
                    blockReason = heuristicResult.reason || "Blocked by heuristic filter";
                    
                                    // Log detailed heuristic analysis
                if (heuristicResult.triggeredRules && heuristicResult.triggeredRules.length > 0) {
                    console.warn(`[HeuristicFilter] Rules triggered:`, {
                        rules: heuristicResult.triggeredRules.map(r => r.name),
                        totalScore: heuristicResult.totalScore,
                        recommendations: heuristicResult.recommendations
                    });
                }
                    
                    break; // Block immediately
                }
                
                // Log warnings for non-blocking rules
                if (heuristicResult.triggeredRules && heuristicResult.triggeredRules.length > 0 && !heuristicResult.detected) {
                    console.info(`[HeuristicFilter] Non-blocking rules triggered:`, {
                        rules: heuristicResult.triggeredRules.map(r => r.name),
                        score: heuristicResult.totalScore
                    });
                }
            }

            // 3. Prompt Injection Detection (Multi-level)
            if (config.promptInjection.enabled) {
                const injectionResult = this.promptInjector.detectAdvanced(content);
                if (injectionResult.detected) {
                    // Décision de blocage basée sur la sévérité et la confiance
                    const shouldBlock = injectionResult.severity === 'critical' || 
                                       (injectionResult.severity === 'high' && injectionResult.confidence > 0.7) ||
                                       (config.promptInjection.level === 'basic' && injectionResult.detected);
                    
                    if (shouldBlock) {
                        blockReason = `Potential prompt injection detected.`;
                        break; // Block immediately
                    } else {
                        // Log warning but continue
                        console.warn(`[PromptInjection] Non-blocking detection:`, {
                            severity: injectionResult.severity,
                            confidence: injectionResult.confidence,
                            techniques: injectionResult.techniques
                        });
                    }
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

            // 6. Content Moderation Check
            if (config.contentModeration.enabled && typeof currentMessages[i].content === 'string') {
                const moderationResult = this.contentModerator.moderate(
                    currentMessages[i].content as string,
                    { role: msg.role, userId: 'unknown' } // Context for better moderation
                );

                // If content should be blocked, set block reason
                if (moderationResult.blocked) {
                    const violationCategories = moderationResult.violations
                        .map(v => v.category)
                        .join(', ');
                    blockReason = `Content blocked by moderation policy: ${violationCategories}`;
                    break;
                }

                // Apply content modifications if any (redaction, etc.)
                if (moderationResult.processedContent && moderationResult.processedContent !== currentMessages[i].content) {
                    currentMessages[i] = { ...currentMessages[i], content: moderationResult.processedContent };
                }

                // Log warnings
                for (const warning of moderationResult.warnings) {
                    console.warn(`[ContentModeration] ${warning}`);
                }
            }

            // 7. Canary Token Insertion
            if (config.canaryTokens.enabled) {
                 // Ensure msg.content is still a string after PII redaction and moderation
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

    private async applyPostSecurityChecks(
        completion: OpenAI.Chat.Completions.ChatCompletion, 
        config: Required<ReskSecurityConfig>, 
        securityInfo: ProcessedSecurityInfo
    ): Promise<OpenAI.Chat.Completions.ChatCompletion> {
        let processedCompletion = completion;
        const responseContent = completion.choices[0]?.message?.content;

        if (!responseContent) {
            return processedCompletion; // No content to check
        }

        // 1. Canary Token Leak Detection
        if (config.canaryTokens.enabled && securityInfo.canaryToken) {
            const leaks = await this.canaryTokenManager.check_for_leaks(
                responseContent, 
                [securityInfo.canaryToken],
                { 
                    responseLength: responseContent.length,
                    model: completion.model,
                    timestamp: new Date().toISOString()
                }
            );
            
            // Log leak detection results
            if (leaks.length > 0) {
                console.warn(`[ReskLLMClient] ${leaks.length} canary token leak(s) detected in response`);
                // Optionally modify response or take other actions based on leaks
            }
        }

        // 2. Content Moderation - Check response content
        if (config.contentModeration.enabled) {
            const moderationResult = this.contentModerator.moderate(
                responseContent,
                { role: 'assistant', userId: 'llm_response' }
            );

            // Log any violations in the response
            if (moderationResult.violations.length > 0) {
                console.warn('[ContentModeration] Violations detected in LLM response:', {
                    violations: moderationResult.violations.map(v => ({
                        category: v.category,
                        severity: v.severity,
                        confidence: v.confidence
                    })),
                    blocked: moderationResult.blocked
                });
            }

            // Apply content modifications to response if needed
            if (moderationResult.processedContent && moderationResult.processedContent !== responseContent) {
                if (processedCompletion.choices[0]?.message) {
                    processedCompletion.choices[0].message.content = moderationResult.processedContent;
                }
            }

            // Log warnings
            for (const warning of moderationResult.warnings) {
                console.warn(`[ContentModeration] Response: ${warning}`);
            }
        }

        // 3. PII Detection (on output - redact if configured)
        if (config.piiDetection.enabled && config.piiDetection.redact) {
            // Pass potentially moderated completion to PII protector
            processedCompletion = this.piiProtector.processCompletionOutput(processedCompletion);
        }
        
        return processedCompletion;
    }
} 