import { SecurityFeatureConfig } from "../types";
import { defaultToxicPatterns } from "./patterns/toxic_content_patterns";
import { defaultProhibitedWords } from "./patterns/prohibited_words";

export interface ContentModerationConfig extends SecurityFeatureConfig {
    severity?: 'low' | 'medium' | 'high';
    actions?: {
        toxic?: 'block' | 'warn' | 'redact' | 'log';
        adult?: 'block' | 'warn' | 'redact' | 'log';
        violence?: 'block' | 'warn' | 'redact' | 'log';
        selfHarm?: 'block' | 'warn' | 'redact' | 'log';
        misinformation?: 'block' | 'warn' | 'redact' | 'log';
    };
    customPatterns?: {
        category: string;
        patterns: RegExp[];
        action: 'block' | 'warn' | 'redact' | 'log';
    }[];
    languageSupport?: string[];
    contextAware?: boolean;
}

export interface ModerationResult {
    blocked: boolean;
    violations: {
        category: string;
        severity: 'low' | 'medium' | 'high';
        confidence: number;
        action: string;
        matches: string[];
        redactedContent?: string;
    }[];
    processedContent?: string;
    warnings: string[];
}

/**
 * Système complet de modération de contenu pour filtrer 
 * les contenus inappropriés, toxiques, violents, etc.
 */
export class ContentModerator {
    private config: Required<ContentModerationConfig>;
    
    // Patterns de base par catégorie et niveau de sévérité
    private readonly moderationPatterns = {
        toxic: {
            high: [
                /\b(kill\s+yourself|kys)\b/gi,
                /\b(go\s+die|die\s+in\s+a\s+fire)\b/gi,
                /\b(hate\s+crimes?|genocide)\b/gi,
                ...defaultToxicPatterns.filter((p: RegExp) => p.toString().includes('terrorism|bomb|kill'))
            ],
            medium: [
                /\b(idiot|stupid|moron|retard)\b/gi,
                /\b(shut\s+up|f[*@#]?ck\s+off)\b/gi,
                ...defaultProhibitedWords.filter((word: string) => ['hate', 'stupid', 'idiot'].includes(word))
                    .map((word: string) => new RegExp(`\\b${word}\\b`, 'gi'))
            ],
            low: [
                /\b(annoying|boring|lame)\b/gi,
                /\b(whatever|meh)\b/gi
            ]
        },
        adult: {
            high: [
                /\b(pornography|explicit\s+sexual|nude\s+photos?)\b/gi,
                /\b(sex\s+videos?|adult\s+content)\b/gi,
                /\b(sexual\s+services?|escort\s+services?)\b/gi
            ],
            medium: [
                /\b(sexual\s+content|erotic|sensual)\b/gi,
                /\b(dating\s+app|hookup)\b/gi
            ],
            low: [
                /\b(romantic|flirting|attraction)\b/gi
            ]
        },
        violence: {
            high: [
                /\b(murder|assassination|terrorist\s+attack)\b/gi,
                /\b(weapons?\s+of\s+mass\s+destruction|bomb\s+making)\b/gi,
                /\b(school\s+shooting|mass\s+shooting)\b/gi,
                /\b(torture|brutally\s+kill)\b/gi
            ],
            medium: [
                /\b(fight|punch|beat\s+up|violence)\b/gi,
                /\b(weapon|gun|knife|sword)\b/gi,
                /\b(war|battle|combat)\b/gi
            ],
            low: [
                /\b(conflict|argument|disagreement)\b/gi,
                /\b(competition|rivalry)\b/gi
            ]
        },
        selfHarm: {
            high: [
                /\b(suicide|self\s+harm|cut\s+myself)\b/gi,
                /\b(end\s+my\s+life|take\s+my\s+own\s+life)\b/gi,
                /\b(ways\s+to\s+die|how\s+to\s+kill\s+myself)\b/gi
            ],
            medium: [
                /\b(depressed|hopeless|worthless)\b/gi,
                /\b(self\s+injury|cutting|burning)\b/gi
            ],
            low: [
                /\b(sad|unhappy|down)\b/gi,
                /\b(stressed|overwhelmed)\b/gi
            ]
        },
        misinformation: {
            high: [
                /\b(covid\s+is\s+fake|vaccines?\s+cause\s+autism)\b/gi,
                /\b(earth\s+is\s+flat|climate\s+change\s+is\s+hoax)\b/gi,
                /\b(election\s+was\s+stolen|fake\s+news\s+media)\b/gi
            ],
            medium: [
                /\b(conspiracy\s+theory|government\s+cover\s*up)\b/gi,
                /\b(mainstream\s+media\s+lies|alternative\s+facts)\b/gi
            ],
            low: [
                /\b(rumor|unconfirmed|allegedly)\b/gi,
                /\b(some\s+say|sources\s+claim)\b/gi
            ]
        }
    };

    constructor(config?: ContentModerationConfig) {
        // Configuration par défaut sécurisée
        this.config = {
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
            contextAware: true,
            ...(config || {})
        };
    }

    /**
     * Modère le contenu texte selon la configuration
     */
    moderate(content: string, context?: { role?: string; userId?: string }): ModerationResult {
        if (!this.config.enabled || !content?.trim()) {
            return {
                blocked: false,
                violations: [],
                processedContent: content,
                warnings: []
            };
        }

        const result: ModerationResult = {
            blocked: false,
            violations: [],
            processedContent: content,
            warnings: []
        };

        // Analyse par catégorie
        for (const [category, severityPatterns] of Object.entries(this.moderationPatterns)) {
            const categoryViolations = this.analyzeCategory(
                content,
                category,
                severityPatterns,
                context
            );

            result.violations.push(...categoryViolations);
        }

        // Analyse des patterns personnalisés
        if (this.config.customPatterns?.length) {
            const customViolations = this.analyzeCustomPatterns(content);
            result.violations.push(...customViolations);
        }

        // Application des actions
        result.blocked = this.shouldBlock(result.violations);
        result.processedContent = this.applyContentActions(content, result.violations);
        result.warnings = this.generateWarnings(result.violations);

        // Logging des violations importantes
        if (result.violations.length > 0) {
            console.warn(`[ContentModerator] ${result.violations.length} violation(s) detected`, {
                categories: result.violations.map(v => v.category),
                blocked: result.blocked,
                context
            });
        }

        return result;
    }

    /**
     * Analyse une catégorie spécifique de contenu
     */
    private analyzeCategory(
        content: string,
        category: string,
        severityPatterns: Record<string, RegExp[]>,
        context?: { role?: string; userId?: string }
    ): ModerationResult['violations'] {
        const violations: ModerationResult['violations'] = [];
        const configuredAction = this.config.actions?.[category as keyof typeof this.config.actions] || 'warn';

        // Vérification par niveau de sévérité (high -> medium -> low)
        const severityLevels: Array<'high' | 'medium' | 'low'> = ['high', 'medium', 'low'];
        
        for (const severity of severityLevels) {
            // Skip si le niveau configuré est plus élevé
            if (this.config.severity === 'high' && severity !== 'high') continue;
            if (this.config.severity === 'medium' && severity === 'low') continue;

            const patterns = severityPatterns[severity] || [];
            const matches: string[] = [];

            for (const pattern of patterns) {
                const found = content.match(pattern);
                if (found) {
                    matches.push(...found);
                }
            }

            if (matches.length > 0) {
                // Calcul de confiance basé sur le nombre de matches et la sévérité
                const baseConfidence = severity === 'high' ? 0.9 : severity === 'medium' ? 0.7 : 0.5;
                const matchConfidence = Math.min(0.9, baseConfidence + (matches.length * 0.1));

                violations.push({
                    category,
                    severity,
                    confidence: matchConfidence,
                    action: configuredAction,
                    matches,
                    redactedContent: this.redactMatches(content, matches)
                });

                // Pour l'efficacité, on s'arrête au premier niveau de sévérité trouvé
                break;
            }
        }

        return violations;
    }

    /**
     * Analyse les patterns personnalisés
     */
    private analyzeCustomPatterns(content: string): ModerationResult['violations'] {
        const violations: ModerationResult['violations'] = [];

        for (const customPattern of this.config.customPatterns || []) {
            const matches: string[] = [];
            
            for (const pattern of customPattern.patterns) {
                const found = content.match(pattern);
                if (found) {
                    matches.push(...found);
                }
            }

            if (matches.length > 0) {
                violations.push({
                    category: customPattern.category,
                    severity: 'medium', // Par défaut pour les patterns personnalisés
                    confidence: 0.8,
                    action: customPattern.action,
                    matches,
                    redactedContent: this.redactMatches(content, matches)
                });
            }
        }

        return violations;
    }

    /**
     * Détermine si le contenu doit être bloqué
     */
    private shouldBlock(violations: ModerationResult['violations']): boolean {
        return violations.some(v => 
            v.action === 'block' && 
            (v.severity === 'high' || (v.severity === 'medium' && v.confidence > 0.7))
        );
    }

    /**
     * Applique les actions sur le contenu (redaction, etc.)
     */
    private applyContentActions(content: string, violations: ModerationResult['violations']): string {
        let processedContent = content;

        for (const violation of violations) {
            if (violation.action === 'redact' && violation.redactedContent) {
                processedContent = violation.redactedContent;
            }
        }

        return processedContent;
    }

    /**
     * Génère les avertissements pour les violations
     */
    private generateWarnings(violations: ModerationResult['violations']): string[] {
        const warnings: string[] = [];

        for (const violation of violations) {
            if (violation.action === 'warn' || violation.action === 'log') {
                warnings.push(
                    `[${violation.category.toUpperCase()}] ${violation.severity} severity violation detected ` +
                    `(confidence: ${(violation.confidence * 100).toFixed(1)}%)`
                );
            }
        }

        return warnings;
    }

    /**
     * Redacte les matches trouvés dans le contenu
     */
    private redactMatches(content: string, matches: string[]): string {
        let redacted = content;
        
        for (const match of matches) {
            const redactedText = '[MODERATED]';
            redacted = redacted.replace(new RegExp(match.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), redactedText);
        }

        return redacted;
    }

    /**
     * Ajoute un pattern personnalisé
     */
    addCustomPattern(category: string, pattern: RegExp, action: 'block' | 'warn' | 'redact' | 'log' = 'warn'): void {
        if (!this.config.customPatterns) {
            this.config.customPatterns = [];
        }

        const existingCategory = this.config.customPatterns.find(cp => cp.category === category);
        if (existingCategory) {
            existingCategory.patterns.push(pattern);
        } else {
            this.config.customPatterns.push({
                category,
                patterns: [pattern],
                action
            });
        }
    }

    /**
     * Met à jour la configuration de modération
     */
    updateConfig(newConfig: Partial<ContentModerationConfig>): void {
        this.config = { ...this.config, ...newConfig };
    }

    /**
     * Obtient des statistiques sur la modération
     */
    getStats(): {
        categoriesCount: number;
        patternsCount: number;
        customPatternsCount: number;
        config: ContentModerationConfig;
    } {
        const patternsCount = Object.values(this.moderationPatterns)
            .reduce((total, severityPatterns) => 
                total + Object.values(severityPatterns).reduce((sum, patterns) => sum + patterns.length, 0), 0);

        return {
            categoriesCount: Object.keys(this.moderationPatterns).length,
            patternsCount,
            customPatternsCount: this.config.customPatterns?.length || 0,
            config: this.config
        };
    }
}