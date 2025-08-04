/**
 * ReskSecurityFilter - Frontend Security Layer
 * 
 * CRITICAL SECURITY WARNING:
 * =====================================
 * This class is designed for FRONTEND ONLY and must NEVER
 * contain API keys. All communications with LLMs must
 * go through a secure backend proxy.
 * 
 * USE ONLY for:
 * - User input validation
 * - Filtering outputs received from backend
 * - Client-side suspicious pattern detection
 * - UX enhancement with immediate feedback
 * 
 * NEVER use for:
 * - Storing API keys
 * - Making direct LLM calls
 * - Replacing backend security
 */

import { InputSanitizer } from '../security/sanitizer';
import { PIIProtector } from '../security/pii_protector';
import { PromptInjectionDetector, InjectionDetectionResult } from '../security/prompt_injection';
import { HeuristicFilter, HeuristicFilterResult } from '../security/heuristic_filter';
import { ContentModerator, ModerationResult } from '../security/content_moderation';
import { CanaryTokenDetector } from '../security/canary_tokens';
import { SecurityCache, CacheConfig } from './security_cache';
import { PerformanceOptimizer } from './performance_optimizer';
import { SIEMIntegration, SIEMConfig } from './siem_integration';

export type ProviderType = 'openai' | 'anthropic' | 'cohere' | 'huggingface' | 'custom';

export interface FrontendSecurityConfig {
    // Modules de sécurité frontend
    inputSanitization?: { enabled: boolean; sanitizeHtml?: boolean };
    piiDetection?: { enabled: boolean; redact: boolean; highlightOnly?: boolean };
    promptInjection?: { enabled: boolean; level: 'basic' | 'advanced'; clientSideOnly?: boolean };
    heuristicFilter?: { enabled: boolean; severity: 'low' | 'medium' | 'high' };
    contentModeration?: { enabled: boolean; severity: 'low' | 'medium' | 'high' };
    canaryDetection?: { enabled: boolean };
    
    // Optimisations frontend
    caching?: CacheConfig;
    performance?: { enableParallel: boolean; timeout: number };
    
    // Intégrations monitoring
    siem?: SIEMConfig;
    
    // Configuration UX
    ui?: {
        showWarnings: boolean;
        blockSubmission: boolean;
        highlightIssues: boolean;
        realTimeValidation: boolean;
    };
}

export interface SecurityValidationResult {
    valid: boolean;
    blocked: boolean;
    warnings: string[];
    errors: string[];
    suggestions: string[];
    details: {
        injection?: InjectionDetectionResult;
        heuristic?: HeuristicFilterResult;
        moderation?: ModerationResult;
        piiDetected?: boolean;
        canaryTokens?: string[];
    };
    performance: {
        totalTime: number;
        moduleTimings: Record<string, number>;
        cacheHits: number;
    };
}

export interface ProviderMessage {
    role: 'system' | 'user' | 'assistant';
    content: string;
    name?: string;
    [key: string]: unknown; // Pour les propriétés spécifiques aux providers
}

export interface ProviderRequest {
    provider: ProviderType;
    model: string;
    messages: ProviderMessage[];
    temperature?: number;
    max_tokens?: number;
    [key: string]: unknown; // Propriétés spécifiques
}

export interface ProviderResponse {
    provider: ProviderType;
    model: string;
    choices: Array<{
        message: ProviderMessage;
        finish_reason?: string;
    }>;
    usage?: {
        prompt_tokens: number;
        completion_tokens: number;
        total_tokens: number;
    };
    [key: string]: unknown; // Propriétés spécifiques
}

/**
 * Classe principale pour la sécurité frontend
 * ATTENTION : Ne contient AUCUNE clé API - Frontend-only
 */
export class ReskSecurityFilter {
    private config: FrontendSecurityConfig;
    private cache: SecurityCache;
    private optimizer: PerformanceOptimizer;
    private siem: SIEMIntegration | null = null;

    // Security modules (frontend-only)
    private inputSanitizer!: InputSanitizer;
    private piiProtector!: PIIProtector;
    private promptInjector!: PromptInjectionDetector;
    private heuristicFilter!: HeuristicFilter;
    private contentModerator!: ContentModerator;
    private canaryDetector!: CanaryTokenDetector;

    constructor(config: FrontendSecurityConfig = {}) {
        // Critical security validation
        this.validateSecurityConstraints();

        this.config = this.mergeDefaultConfig(config);
        
        // Initialize optimizations
        this.cache = new SecurityCache(this.config.caching);
        this.optimizer = new PerformanceOptimizer(this.config.performance);
        
        // Initialize SIEM if configured
        if (this.config.siem?.enabled) {
            this.siem = new SIEMIntegration(this.config.siem);
        }

        // Initialize security modules
        this.initializeSecurityModules();

        console.info('[ReskSecurityFilter] Frontend security layer initialized');
        console.warn('[SECURITY] This is a FRONTEND-ONLY security layer. Use backend proxy for LLM API calls.');
    }

    /**
     * Validation critique des contraintes de sécurité
     */
    private validateSecurityConstraints(): void {
        // Vérifier qu'on est bien côté frontend
        if (typeof window === 'undefined' && typeof process !== 'undefined' && process.env) {
            console.warn('[SECURITY WARNING] ReskSecurityFilter detected server environment. Use ReskLLMClient for backend.');
        }

        // Scanner les variables globales pour des clés API accidentelles
        const dangerousKeys = ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'COHERE_API_KEY'];
        dangerousKeys.forEach(key => {
            let foundInWindow = false;
            let foundInStorage = false;
            
            // Vérifier dans window (navigateur)
            if (typeof window !== 'undefined') {
                foundInWindow = !!(window as any)[key];
                foundInStorage = !!(localStorage && localStorage.getItem(key));
            }
            
            // Vérifier dans global.localStorage (tests)
            if (typeof global !== 'undefined' && (global as any).localStorage) {
                foundInStorage = foundInStorage || !!((global as any).localStorage.getItem(key));
            }
            
            if (foundInWindow || foundInStorage) {
                console.error(`[CRITICAL SECURITY RISK] API Key "${key}" detected in frontend! Remove immediately!`);
                throw new Error(`Security violation: API key detected in frontend environment`);
            }
        });
    }

    /**
     * Fusion avec la configuration par défaut
     */
    private mergeDefaultConfig(userConfig: FrontendSecurityConfig): FrontendSecurityConfig {
        return {
            inputSanitization: { enabled: true, sanitizeHtml: true, ...userConfig.inputSanitization },
            piiDetection: { enabled: true, redact: false, highlightOnly: true, ...userConfig.piiDetection },
            promptInjection: { enabled: true, level: 'basic', clientSideOnly: true, ...userConfig.promptInjection },
            heuristicFilter: { enabled: true, severity: 'medium', ...userConfig.heuristicFilter },
            contentModeration: { enabled: true, severity: 'medium', ...userConfig.contentModeration },
            canaryDetection: { enabled: true, ...userConfig.canaryDetection },
            caching: { enabled: true, maxSize: 1000, ttl: 300000, strategy: 'lru', ...userConfig.caching },
            performance: { enableParallel: true, timeout: 5000, ...userConfig.performance },
            ui: { 
                showWarnings: true, 
                blockSubmission: false, // Par défaut, ne pas bloquer côté client
                highlightIssues: true, 
                realTimeValidation: true,
                ...userConfig.ui 
            },
            siem: userConfig.siem
        };
    }

    /**
     * Initialisation des modules de sécurité
     */
    private initializeSecurityModules(): void {
        this.inputSanitizer = new InputSanitizer(this.config.inputSanitization);
        this.piiProtector = new PIIProtector(this.config.piiDetection);
        this.promptInjector = new PromptInjectionDetector(this.config.promptInjection);
        this.heuristicFilter = new HeuristicFilter(this.config.heuristicFilter);
        this.contentModerator = new ContentModerator(this.config.contentModeration);
        this.canaryDetector = new CanaryTokenDetector();
    }

    /**
     * Validation complète d'une requête avant envoi au backend
     */
    async validateRequest(request: ProviderRequest): Promise<SecurityValidationResult> {
        return this.optimizer.executeValidation(
            `request_${this.generateCacheKey('request', request)}`,
            async () => {
                const startTime = performance.now();
                const moduleTimings: Record<string, number> = {};
                
                // Cache key based on content
                const cacheKey = this.generateCacheKey('request', request);
                const cached = this.cache.get<SecurityValidationResult>(cacheKey);
                if (cached) {
                    return { ...cached, performance: { ...cached.performance, cacheHits: 1 } };
                }

                const result: SecurityValidationResult = {
                    valid: true,
                    blocked: false,
                    warnings: [],
                    errors: [],
                    suggestions: [],
                    details: {},
                    performance: { totalTime: 0, moduleTimings: {}, cacheHits: 0 }
                };

                try {
                    // Normaliser les messages selon le provider
                    const normalizedMessages = this.normalizeProviderMessages(request);

                    // Exécution parallèle des validations si activée
                    if (this.config.performance?.enableParallel) {
                        await this.runParallelValidations(normalizedMessages, result, moduleTimings);
                    } else {
                        await this.runSequentialValidations(normalizedMessages, result, moduleTimings);
                    }

                    // Déterminer le statut final
                    this.determineValidationStatus(result);

                    // Envoyer aux systèmes de monitoring
                    if (this.siem) {
                        await this.siem.logSecurityEvent('request_validation', {
                            result: result,
                            provider: request.provider,
                            model: request.model
                        });
                    }

                } catch (error) {
                    result.valid = false;
                    result.errors.push(`Validation error: ${error}`);
                    console.error('[ReskSecurityFilter] Validation failed:', error);
                }

                // Finaliser les métriques de performance
                result.performance.totalTime = performance.now() - startTime;
                result.performance.moduleTimings = moduleTimings;

                // Cache du résultat
                this.cache.set(cacheKey, result);

                return result;
            }
        );
    }

    /**
     * Validation d'une réponse reçue du backend
     */
    async validateResponse(response: ProviderResponse): Promise<SecurityValidationResult> {
        return this.optimizer.executeValidation(
            `response_${this.generateCacheKey('response', response)}`,
            async () => {
                const startTime = performance.now();
                const moduleTimings: Record<string, number> = {};

                const cacheKey = this.generateCacheKey('response', response);
                const cached = this.cache.get<SecurityValidationResult>(cacheKey);
                if (cached) {
                    return { ...cached, performance: { ...cached.performance, cacheHits: 1 } };
                }

                const result: SecurityValidationResult = {
                    valid: true,
                    blocked: false,
                    warnings: [],
                    errors: [],
                    suggestions: [],
                    details: {},
                    performance: { totalTime: 0, moduleTimings: {}, cacheHits: 0 }
                };

                try {
                    // Extraire le contenu de la réponse
                    const responseContent = this.extractResponseContent(response);
                    
                    if (responseContent) {
                        // Validation du contenu de la réponse
                        await this.validateResponseContent(responseContent, result, moduleTimings);
                    }

                    // Envoyer aux systèmes de monitoring
                    if (this.siem) {
                        await this.siem.logSecurityEvent('response_validation', {
                            result: result,
                            provider: response.provider,
                            model: response.model
                        });
                    }

                } catch (error) {
                    result.valid = false;
                    result.errors.push(`Response validation error: ${error}`);
                }

                result.performance.totalTime = performance.now() - startTime;
                result.performance.moduleTimings = moduleTimings;

                this.cache.set(cacheKey, result);
                return result;
            }
        );
    }

    /**
     * Normalisation des messages selon le provider
     */
    private normalizeProviderMessages(request: ProviderRequest): ProviderMessage[] {
        switch (request.provider) {
            case 'openai':
                return request.messages; // Format standard
            
            case 'anthropic':
                // Claude peut avoir des spécificités
                return request.messages.map(msg => ({
                    role: msg.role,
                    content: msg.content,
                    name: msg.name
                }));
            
            case 'cohere':
                // Cohere a un format légèrement différent
                return request.messages.map(msg => ({
                    role: msg.role === 'assistant' ? 'chatbot' as any : msg.role,
                    content: msg.content
                }));
            
            case 'huggingface':
                // HuggingFace peut nécessiter une conversion
                return request.messages;
            
            default:
                return request.messages;
        }
    }

    /**
     * Extraction du contenu de réponse selon le provider
     */
    private extractResponseContent(response: ProviderResponse): string {
        if (!response.choices || response.choices.length === 0) {
            return '';
        }

        const firstChoice = response.choices[0];
        
        switch (response.provider) {
            case 'openai':
            case 'anthropic':
            case 'huggingface':
                return firstChoice.message?.content || '';
            
            case 'cohere':
                // Cohere pourrait avoir un format différent
                return firstChoice.message?.content || '';
            
            default:
                return firstChoice.message?.content || '';
        }
    }

    /**
     * Exécution parallèle des validations (optimisé)
     */
    private async runParallelValidations(
        messages: ProviderMessage[], 
        result: SecurityValidationResult, 
        moduleTimings: Record<string, number>
    ): Promise<void> {
        const userMessages = messages.filter(msg => msg.role === 'user');
        const userContent = userMessages.map(msg => msg.content).join(' ');

        if (!userContent.trim()) return;

        const validationPromises = [];

        // Injection detection
        if (this.config.promptInjection?.enabled) {
            validationPromises.push(
                this.timeModule('injection', async () => {
                    result.details.injection = this.promptInjector.detectAdvanced(userContent);
                })
            );
        }

        // Heuristic filter
        if (this.config.heuristicFilter?.enabled) {
            validationPromises.push(
                this.timeModule('heuristic', async () => {
                    result.details.heuristic = this.heuristicFilter.filter(userContent);
                })
            );
        }

        // Content moderation
        if (this.config.contentModeration?.enabled) {
            validationPromises.push(
                this.timeModule('moderation', async () => {
                    result.details.moderation = this.contentModerator.moderate(userContent);
                })
            );
        }

        // PII detection
        if (this.config.piiDetection?.enabled) {
            validationPromises.push(
                this.timeModule('pii', async () => {
                    // Pour le frontend, on détecte mais on ne redacte pas forcément
                    const hasPII = userContent.match(/\b[\w._%+-]+@[\w.-]+\.[A-Z|a-z]{2,}\b/);
                    result.details.piiDetected = !!hasPII;
                })
            );
        }

        // Canary token detection
        if (this.config.canaryDetection?.enabled) {
            validationPromises.push(
                this.timeModule('canary', async () => {
                    const canaryResult = this.canaryDetector.detect(userContent);
                    if (canaryResult.canary_tokens_found && canaryResult.details?.length > 0) {
                        result.details.canaryTokens = canaryResult.details;
                    }
                })
            );
        }

        // Attendre toutes les validations
        const timingResults = await Promise.all(validationPromises);
        timingResults.forEach(timing => {
            Object.assign(moduleTimings, timing);
        });
    }

    /**
     * Validation séquentielle (fallback)
     */
    private async runSequentialValidations(
        messages: ProviderMessage[], 
        result: SecurityValidationResult, 
        moduleTimings: Record<string, number>
    ): Promise<void> {
        const userContent = messages
            .filter(msg => msg.role === 'user')
            .map(msg => msg.content)
            .join(' ');

        if (!userContent.trim()) return;

        // Injection
        if (this.config.promptInjection?.enabled) {
            const timing = await this.timeModule('injection', async () => {
                result.details.injection = this.promptInjector.detectAdvanced(userContent);
            });
            Object.assign(moduleTimings, timing);
        }

        // Autres validations...
        // (Implémentation similaire mais séquentielle)
    }

    /**
     * Validation du contenu de réponse
     */
    private async validateResponseContent(
        content: string, 
        result: SecurityValidationResult, 
        moduleTimings: Record<string, number>
    ): Promise<void> {
        // Validation de la réponse pour détection de fuites, contenu inapproprié, etc.
        
        // Canary token detection dans la réponse
        if (this.config.canaryDetection?.enabled) {
            const timing = await this.timeModule('canary_response', async () => {
                const canaryResult = this.canaryDetector.detect(content);
                if (canaryResult.canary_tokens_found) {
                    result.warnings.push('Canary tokens detected in response');
                    result.details.canaryTokens = canaryResult.details;
                }
            });
            Object.assign(moduleTimings, timing);
        }

        // Content moderation sur la réponse
        if (this.config.contentModeration?.enabled) {
            const timing = await this.timeModule('moderation_response', async () => {
                const moderationResult = this.contentModerator.moderate(content);
                if (moderationResult.violations.length > 0) {
                    result.warnings.push('Content moderation issues in response');
                    result.details.moderation = moderationResult;
                }
            });
            Object.assign(moduleTimings, timing);
        }
    }

    /**
     * Détermination du statut final de validation
     */
    private determineValidationStatus(result: SecurityValidationResult): void {
        // Injection détectée
        if (result.details.injection?.detected) {
            if (result.details.injection.severity === 'critical' || result.details.injection.confidence > 0.8) {
                result.blocked = this.config.ui?.blockSubmission || false;
                result.errors.push(`High-confidence prompt injection detected (${(result.details.injection.confidence * 100).toFixed(1)}%)`);
            } else {
                result.warnings.push('Potential prompt injection detected');
            }
        }

        // Modération de contenu
        if (result.details.moderation?.violations?.length && result.details.moderation.violations.length > 0) {
            // Toujours ajouter un avertissement quand il y a des violations
            result.warnings.push(`Content moderation detected: ${result.details.moderation.violations.map(v => v.category).join(', ')}`);
            
            // Ajouter une erreur et bloquer si nécessaire
            if (result.details.moderation.blocked && this.config.ui?.blockSubmission) {
                result.blocked = true;
                result.errors.push('Content blocked by moderation policy');
            }
        }

        // Heuristique
        if (result.details.heuristic?.detected) {
            result.warnings.push(result.details.heuristic.reason || 'Heuristic filter triggered');
        }

        // PII détectée
        if (result.details.piiDetected) {
            result.warnings.push('PII (Personally Identifiable Information) detected');
            result.suggestions.push('Consider removing personal information before submission');
        }

        // Canary tokens
        if (result.details.canaryTokens?.length) {
            result.warnings.push('Canary tokens detected - potential data leak');
        }

        // Statut global
        result.valid = result.errors.length === 0;
    }

    /**
     * Utilitaire pour mesurer le temps d'exécution des modules
     */
    private async timeModule(moduleName: string, fn: () => Promise<void>): Promise<Record<string, number>> {
        const start = performance.now();
        await fn();
        const duration = performance.now() - start;
        return { [moduleName]: duration };
    }

    /**
     * Génération de clé de cache
     */
    private generateCacheKey(type: string, data: any): string {
        const content = JSON.stringify(data);
        // Hash simple pour la clé de cache
        let hash = 0;
        for (let i = 0; i < content.length; i++) {
            const char = content.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return `${type}_${Math.abs(hash)}`;
    }

    /**
     * Nettoyage des ressources
     */
    dispose(): void {
        this.cache.clear();
        if (this.siem) {
            this.siem.dispose();
        }
        console.info('[ReskSecurityFilter] Resources cleaned up');
    }

    /**
     * Obtention des statistiques de performance
     */
    getPerformanceStats(): {
        cacheStats: any;
        averageProcessingTime: number;
        totalValidations: number;
    } {
        const optimizerMetrics = this.optimizer.getMetrics();
        return {
            cacheStats: this.cache.getStats(),
            averageProcessingTime: optimizerMetrics.averageProcessingTime,
            totalValidations: optimizerMetrics.totalValidations
        };
    }
}