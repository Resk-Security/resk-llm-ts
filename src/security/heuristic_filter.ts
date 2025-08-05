import { SecurityFeatureConfig } from "../index";
import { defaultInjectionPatterns } from "./patterns/llm_injection_patterns"; // Import default injection patterns

export interface CustomHeuristicRule {
    id: string;
    name: string;
    description?: string;
    category: string;
    priority: number; // 1-10, 10 = highest priority
    enabled: boolean;
    conditions: {
        patterns?: RegExp[];
        keywords?: string[];
        minLength?: number;
        maxLength?: number;
        contentType?: 'user' | 'system' | 'assistant' | 'any';
        contextual?: {
            previousMessages?: number; // Check last N messages
            userRole?: string;
            timeWindow?: number; // Minutes
        };
    };
    actions: {
        block?: boolean;
        warn?: boolean;
        log?: boolean;
        score?: number; // Penalty score (0-100)
        customMessage?: string;
    };
    metadata?: Record<string, unknown>;
}

export interface HeuristicFilterResult {
    detected: boolean;
    reason: string | null;
    triggeredRules: CustomHeuristicRule[];
    totalScore: number;
    recommendations: string[];
}

export interface HeuristicFilterConfig extends SecurityFeatureConfig {
    patterns?: RegExp[];
    customRules?: CustomHeuristicRule[];
    scoreThreshold?: number; // Threshold for blocking based on accumulated score
    severity?: 'low' | 'medium' | 'high';
    industryProfile?: 'general' | 'healthcare' | 'finance' | 'education' | 'government';
    enableContextualAnalysis?: boolean;
}

// Profils spécifiques par industrie
const industryRules: Record<string, CustomHeuristicRule[]> = {
    healthcare: [
        {
            id: 'health_pii',
            name: 'Healthcare PII Protection',
            category: 'compliance',
            priority: 9,
            enabled: true,
            conditions: {
                patterns: [/\b(patient|medical\s+record|diagnosis|prescription)/gi],
                keywords: ['hipaa', 'medical', 'health record']
            },
            actions: { block: true, score: 85, customMessage: 'Healthcare data detected - HIPAA compliance required' }
        }
    ],
    finance: [
        {
            id: 'financial_data',
            name: 'Financial Information Protection', 
            category: 'compliance',
            priority: 9,
            enabled: true,
            conditions: {
                patterns: [/\b(account\s+number|routing\s+number|credit\s+score|ssn)/gi],
                keywords: ['bank', 'financial', 'account']
            },
            actions: { block: true, score: 90, customMessage: 'Financial data detected - PCI compliance required' }
        }
    ],
    education: [
        {
            id: 'student_data',
            name: 'Student Data Protection',
            category: 'compliance', 
            priority: 8,
            enabled: true,
            conditions: {
                patterns: [/\b(student\s+id|grade|academic\s+record)/gi],
                keywords: ['ferpa', 'student', 'academic']
            },
            actions: { warn: true, score: 70, customMessage: 'Student data detected - FERPA compliance required' }
        }
    ]
};

// Combine multiple pattern sources for heuristics if needed
const defaultSuspiciousPatterns: RegExp[] = [
    ...defaultInjectionPatterns, // Include injection patterns as suspicious
    // Add any other general heuristic patterns here if necessary
    /\bsecret\s+key\b/i,
    /\bconfidential\b/i,
];

export class HeuristicFilter {
    private config: HeuristicFilterConfig;
    private patterns: RegExp[];
    private customRules: CustomHeuristicRule[];
    private messageHistory: Array<{ content: string; role: string; timestamp: number }> = [];

    constructor(config?: HeuristicFilterConfig) {
        this.config = {
            enabled: true,
            scoreThreshold: 70,
            severity: 'medium',
            industryProfile: 'general',
            enableContextualAnalysis: false,
            ...(config || {}),
        };
        
        // Use imported defaults + user-provided patterns
        this.patterns = [...defaultSuspiciousPatterns, ...(this.config.patterns || [])];
        
        // Initialize custom rules
        this.customRules = [...(this.config.customRules || [])];
        
        // Add industry-specific rules
        if (this.config.industryProfile && this.config.industryProfile !== 'general') {
            const industrySpecificRules = industryRules[this.config.industryProfile] || [];
            this.customRules.push(...industrySpecificRules);
        }
        
        // Sort rules by priority (highest first)
        this.customRules.sort((a, b) => b.priority - a.priority);
    }

    /**
     * Add a custom suspicious pattern (regex) - legacy method
     */
    addSuspiciousPattern(pattern: RegExp): void {
        this.patterns.push(pattern);
    }

    /**
     * Add a custom heuristic rule
     */
    addCustomRule(rule: CustomHeuristicRule): void {
        // Remove existing rule with same ID if any
        this.customRules = this.customRules.filter(r => r.id !== rule.id);
        
        // Add new rule
        this.customRules.push(rule);
        
        // Re-sort by priority
        this.customRules.sort((a, b) => b.priority - a.priority);
    }

    /**
     * Remove a custom rule by ID
     */
    removeCustomRule(ruleId: string): boolean {
        const initialLength = this.customRules.length;
        this.customRules = this.customRules.filter(r => r.id !== ruleId);
        return this.customRules.length < initialLength;
    }

    /**
     * Filter the input text based on heuristic patterns and custom rules.
     */
    filter(text: string, context?: { role?: string; userId?: string }): HeuristicFilterResult {
        if (!this.config.enabled || !text) {
            return {
                detected: false,
                reason: null,
                triggeredRules: [],
                totalScore: 0,
                recommendations: []
            };
        }

        const result: HeuristicFilterResult = {
            detected: false,
            reason: null,
            triggeredRules: [],
            totalScore: 0,
            recommendations: []
        };

        // Store message for contextual analysis if enabled
        if (this.config.enableContextualAnalysis && context?.role) {
            this.addToHistory(text, context.role);
        }

        // 1. Legacy pattern matching
        const legacyResult = this.checkLegacyPatterns(text);
        if (legacyResult.detected) {
            result.detected = true;
            result.reason = legacyResult.reason;
            result.totalScore += 50; // Default score for legacy patterns
        }

        // 2. Custom rules evaluation
        const rulesResult = this.evaluateCustomRules(text, context);
        result.triggeredRules = rulesResult.triggeredRules;
        result.totalScore += rulesResult.score;

        // 3. Determine final detection status
        const shouldBlock = result.totalScore >= this.config.scoreThreshold! ||
                           result.triggeredRules.some(rule => rule.actions.block);

        if (shouldBlock) {
            result.detected = true;
            if (!result.reason) {
                const mainRule = result.triggeredRules[0];
                result.reason = mainRule?.actions.customMessage || 
                               `Custom rule triggered: ${mainRule?.name}` || 
                               'Score threshold exceeded';
            }
        }

        // 4. Generate recommendations
        result.recommendations = this.generateRecommendations(result);

        // 5. Logging
        if (result.detected || result.triggeredRules.length > 0) {
            console.warn(`[HeuristicFilter] Analysis complete:`, {
                detected: result.detected,
                score: result.totalScore,
                threshold: this.config.scoreThreshold,
                triggeredRules: result.triggeredRules.map(r => r.name),
                context: context
            });
        }

        return result;
    }

    /**
     * Legacy pattern matching (backward compatibility)
     */
    private checkLegacyPatterns(text: string): { detected: boolean; reason: string | null } {
        // Limit text length to prevent ReDoS attacks
        const maxTextLength = 10000;
        const testText = text.length > maxTextLength ? text.substring(0, maxTextLength) : text;
        
        for (const pattern of this.patterns) {
            try {
                pattern.lastIndex = 0; // Reset state for global regex
                
                // Add timeout protection for regex execution
                const startTime = Date.now();
                const result = pattern.test(testText);
                const executionTime = Date.now() - startTime;
                
                // If regex takes too long, skip it and log warning
                if (executionTime > 100) { // 100ms timeout
                    console.warn(`[HeuristicFilter] Slow regex detected: ${pattern.toString()}, execution time: ${executionTime}ms`);
                    continue;
                }
                
                if (result) {
                    const reason = `Matched legacy heuristic pattern: ${pattern.toString()}`;
                    return { detected: true, reason };
                }
            } catch (error) {
                console.error(`[HeuristicFilter] Regex error for pattern ${pattern.toString()}:`, error);
                continue;
            }
        }
        return { detected: false, reason: null };
    }

    /**
     * Evaluate custom rules against the text
     */
    private evaluateCustomRules(text: string, context?: { role?: string; userId?: string }): {
        triggeredRules: CustomHeuristicRule[];
        score: number;
    } {
        const triggeredRules: CustomHeuristicRule[] = [];
        let totalScore = 0;

        for (const rule of this.customRules) {
            if (!rule.enabled) continue;

            let ruleMatched = false;
            const conditions = rule.conditions;

            // Check content type filter
            if (conditions.contentType && conditions.contentType !== 'any') {
                if (context?.role !== conditions.contentType) {
                    continue;
                }
            }

            // Check length constraints
            if (conditions.minLength && text.length < conditions.minLength) continue;
            if (conditions.maxLength && text.length > conditions.maxLength) continue;

            // Check regex patterns
            if (conditions.patterns) {
                const maxTextLength = 10000;
                const testText = text.length > maxTextLength ? text.substring(0, maxTextLength) : text;
                
                for (const pattern of conditions.patterns) {
                    try {
                        pattern.lastIndex = 0;
                        
                        // Add timeout protection for regex execution
                        const startTime = Date.now();
                        const result = pattern.test(testText);
                        const executionTime = Date.now() - startTime;
                        
                        // If regex takes too long, skip it and log warning
                        if (executionTime > 100) { // 100ms timeout
                            console.warn(`[HeuristicFilter] Slow custom rule regex detected: ${pattern.toString()}, execution time: ${executionTime}ms`);
                            continue;
                        }
                        
                        if (result) {
                            ruleMatched = true;
                            break;
                        }
                    } catch (error) {
                        console.error(`[HeuristicFilter] Custom rule regex error for pattern ${pattern.toString()}:`, error);
                        continue;
                    }
                }
            }

            // Check keywords
            if (!ruleMatched && conditions.keywords) {
                const textLower = text.toLowerCase();
                for (const keyword of conditions.keywords) {
                    if (textLower.includes(keyword.toLowerCase())) {
                        ruleMatched = true;
                        break;
                    }
                }
            }

            // Contextual analysis
            if (!ruleMatched && conditions.contextual && this.config.enableContextualAnalysis) {
                ruleMatched = this.checkContextualConditions(text, conditions.contextual);
            }

            // If rule matched, add to results
            if (ruleMatched) {
                triggeredRules.push(rule);
                totalScore += rule.actions.score || 0;

                // Log individual rule trigger
                console.info(`[HeuristicFilter] Rule triggered: ${rule.name} (${rule.category})`);
                
                // Break if this is a blocking rule and we want to stop early
                if (rule.actions.block) {
                    break;
                }
            }
        }

        return { triggeredRules, score: totalScore };
    }

    /**
     * Check contextual conditions against message history
     */
    private checkContextualConditions(text: string, contextual: NonNullable<CustomHeuristicRule['conditions']['contextual']>): boolean {
        if (!contextual.previousMessages) return false;

        const recentMessages = this.messageHistory.slice(-contextual.previousMessages);
        
        // Check if pattern appears in recent messages
        const combinedText = recentMessages.map(m => m.content).join(' ') + ' ' + text;
        
        // Simple check for repeated patterns or escalating behavior
        const words = text.toLowerCase().split(/\s+/);
        for (const word of words) {
            const occurrences = (combinedText.toLowerCase().match(new RegExp(word, 'g')) || []).length;
            if (occurrences > 3) { // Repeated words across context
                return true;
            }
        }

        return false;
    }

    /**
     * Add message to history for contextual analysis
     */
    private addToHistory(content: string, role: string): void {
        this.messageHistory.push({
            content,
            role,
            timestamp: Date.now()
        });

        // Keep only last 10 messages and clean up old ones (> 1 hour)
        const oneHourAgo = Date.now() - (60 * 60 * 1000);
        this.messageHistory = this.messageHistory
            .filter(m => m.timestamp > oneHourAgo)
            .slice(-10);
    }

    /**
     * Generate recommendations based on analysis results
     */
    private generateRecommendations(result: HeuristicFilterResult): string[] {
        const recommendations: string[] = [];

        if (result.totalScore > 80) {
            recommendations.push('Consider implementing stricter input validation');
        }

        if (result.triggeredRules.some(r => r.category === 'compliance')) {
            recommendations.push('Review compliance requirements for detected content type');
        }

        if (result.triggeredRules.length > 2) {
            recommendations.push('Multiple security rules triggered - review content thoroughly');
        }

        return recommendations;
    }

    /**
     * Create a rule for a specific industry/use case
     */
    createIndustryRule(industry: string, patterns: RegExp[], action: 'block' | 'warn' | 'log' = 'warn'): CustomHeuristicRule {
        return {
            id: `industry_${industry}_${Date.now()}`,
            name: `${industry.charAt(0).toUpperCase() + industry.slice(1)} Industry Rule`,
            category: 'industry',
            priority: 7,
            enabled: true,
            conditions: { patterns },
            actions: {
                [action]: true,
                score: action === 'block' ? 90 : action === 'warn' ? 60 : 30,
                customMessage: `Content flagged for ${industry} industry compliance`
            }
        };
    }

    /**
     * Get statistics about the current rules
     */
    getStats(): {
        totalRules: number;
        enabledRules: number;
        rulesByCategory: Record<string, number>;
        rulesByPriority: Record<number, number>;
        industryProfile: string;
    } {
        const stats = {
            totalRules: this.customRules.length,
            enabledRules: this.customRules.filter(r => r.enabled).length,
            rulesByCategory: {} as Record<string, number>,
            rulesByPriority: {} as Record<number, number>,
            industryProfile: this.config.industryProfile || 'general'
        };

        // Group by category
        for (const rule of this.customRules) {
            stats.rulesByCategory[rule.category] = (stats.rulesByCategory[rule.category] || 0) + 1;
            stats.rulesByPriority[rule.priority] = (stats.rulesByPriority[rule.priority] || 0) + 1;
        }

        return stats;
    }

    /**
     * Export rules configuration
     */
    exportRules(): CustomHeuristicRule[] {
        return this.customRules.map(rule => ({ ...rule })); // Deep copy
    }

    /**
     * Import rules configuration
     */
    importRules(rules: CustomHeuristicRule[]): void {
        this.customRules = rules.map(rule => ({ ...rule })); // Deep copy
        this.customRules.sort((a, b) => b.priority - a.priority);
    }

    /**
     * Update filter configuration
     */
    updateConfig(newConfig: Partial<HeuristicFilterConfig>): void {
        this.config = { ...this.config, ...newConfig };
        
        // Reinitialize if industry profile changed
        if (newConfig.industryProfile && newConfig.industryProfile !== this.config.industryProfile) {
            // Remove old industry rules and add new ones
            this.customRules = this.customRules.filter(r => r.category !== 'compliance');
            if (newConfig.industryProfile !== 'general') {
                const industrySpecificRules = industryRules[newConfig.industryProfile] || [];
                this.customRules.push(...industrySpecificRules);
                this.customRules.sort((a, b) => b.priority - a.priority);
            }
        }
    }
} 