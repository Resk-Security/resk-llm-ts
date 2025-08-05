import { type PromptInjectionConfig } from "../types";

import { TextNormalizer } from "./text_normalizer";

export interface InjectionDetectionResult {
    detected: boolean;
    confidence: number;
    detectionLevel: 'low' | 'medium' | 'high';
    matchedPatterns: string[];
    techniques: string[];
    severity: 'low' | 'medium' | 'high' | 'critical';
}

export class PromptInjectionDetector {
    private config: PromptInjectionConfig;
    private textNormalizer: TextNormalizer;
    
    // Patterns organisés par niveau de sévérité et technique
    private readonly injectionPatterns = {
        // Niveau LOW - Détection basique
        low: {
            directOverride: [
                /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|context)/gi,
                /forget\s+(everything|all)\s+(you\s+)?(know|learned)/gi,
                /disregard\s+(the\s+)?(above|previous|prior)/gi
            ],
            roleSwitch: [
                /you\s+are\s+now\s+(a\s+)?(?:different|new)\s+(?:ai|assistant|model)/gi,
                /from\s+now\s+on[,\s]*(?:you\s+)?(?:are|act\s+like|pretend)/gi
            ],
            systemOverride: [
                /system[:\s]*(?:end|stop|override|reset|new)/gi,
                /end\s+of\s+(?:system|instructions?)/gi
            ]
        },
        
        // Niveau MEDIUM - Techniques sophistiquées  
        medium: {
            encoding: [
                /base64[:\s]*[A-Za-z0-9+/=]{20,}/gi,
                /hex[:\s]*[0-9a-fA-F]{20,}/gi,
                /(?:rot13|caesar|encode)/gi
            ],
            contextBreak: [
                /\*{3,}|-{3,}|={3,}/g, // Separators
                /(?:start|begin|end)\s+(?:new|fresh)\s+(?:context|conversation|session)/gi,
                /(?:context|conversation)\s+(?:switch|change|reset)/gi
            ],
            jailbreak: [
                /jailbreak|prison\s+break|escape\s+mode/gi,
                /developer\s+mode|debug\s+mode|admin\s+mode/gi,
                /dan\s+mode|evil\s+mode|chaos\s+mode/gi
            ],
            repetition: [
                /(.{10,})\1{3,}/g, // Repeated patterns
                /(repeat|say|output)\s+.*\1.*\1/gi
            ]
        },
        
        // Niveau HIGH - Attaques avancées
        high: {
            indirection: [
                /translate\s+to\s+(?:code|programming|markup)/gi,
                /encode\s+as\s+(?:json|xml|yaml|markdown)/gi,
                /format\s+as\s+(?:table|list|code)/gi
            ],
            embedding: [
                /<!--[\s\S]*?-->/g, // HTML comments
                /\/\*[\s\S]*?\*\//g, // CSS/JS comments
                /(?:hidden|invisible|transparent)[:\s]*(?:text|content|message)/gi
            ],
            socialEngineering: [
                /(?:my|our)\s+(?:grandmother|grandma|mother|mom)\s+(?:died|passed\s+away)/gi,
                /emergency|urgent|critical|important/gi,
                /(?:help|save|rescue)\s+(?:me|us|someone)/gi,
                /(?:legal|authorized|official)\s+(?:request|requirement)/gi
            ],
            multilingual: [
                /说|говори|parlez|sprechen|話す/gi, // "Say/speak" in other languages
                /翻译|переводить|traduire|übersetzen|翻訳/gi // "Translate" in other languages
            ]
        }
    };

    // Techniques spécialisées par catégorie
    private readonly advancedTechniques = {
        tokenManipulation: [
            /\[INST\]|\[\/INST\]/gi, // Llama instruction tokens
            /<\|im_start\||<\|im_end\|>/gi, // ChatML tokens
            /<\|system\|>|<\|user\|>|<\|assistant\|>/gi,
            /<s>|<\/s>/gi // Special tokens
        ],
        promptLeaking: [
            /show\s+(?:me\s+)?(?:your|the)\s+(?:initial|original|system)\s+(?:prompt|instructions)/gi,
            /what\s+(?:are|were)\s+(?:your|the)\s+(?:original|initial)\s+(?:instructions|rules)/gi,
            /repeat\s+(?:your|the)\s+(?:first|initial|system)\s+(?:message|prompt)/gi
        ],
        adversarialSuffix: [
            /\.{10,}/, // Long sequences of dots
            /\s+describing\.\+\s+represent\s+Teamsares/gi, // Known adversarial suffix
            /\bdescribing\.\+\\+\bdescriptive\b/gi
        ],
        payloadInjection: [
            /<script\b[^>]*>[\s\S]*?<\/script[\s>]/gi,
            /javascript\s*:\s*/gi,
            /(?:on\w+\s*=|href\s*=\s*["']?javascript)/gi
        ]
    };

    constructor(config?: PromptInjectionConfig) {
        this.config = {
            enabled: true,
            level: 'basic',
            ...(config || {}),
        };
        
        // Initialize text normalizer for better pattern matching
        this.textNormalizer = new TextNormalizer({
            enabled: true,
            normalizeUnicode: true,
            normalizeSpacing: true,
            normalizeCase: true,
            normalizeObfuscation: true,
            normalizeHomoglyphs: true,
        });
    }

    /**
     * Détection simple (compatible avec l'ancienne méthode)
     */
    detect(text: string): boolean {
        const result = this.detectAdvanced(text);
        return result.detected;
    }

    /**
     * Détection avancée avec niveaux granulaires
     */
    detectAdvanced(text: string): InjectionDetectionResult {
        if (!this.config.enabled || !text) {
            return {
                detected: false,
                confidence: 0,
                detectionLevel: 'low',
                matchedPatterns: [],
                techniques: [],
                severity: 'low'
            };
        }

        const result: InjectionDetectionResult = {
            detected: false,
            confidence: 0,
            detectionLevel: 'low',
            matchedPatterns: [],
            techniques: [],
            severity: 'low'
        };

        // Analyse par niveau selon la configuration
        const levelsToCheck = this.getLevelsToCheck();
        
        for (const level of levelsToCheck) {
            this.analyzeLevel(text, level, result);
        }

        // Analyse des techniques avancées si niveau suffisant
        if (this.config.level === 'advanced' || result.confidence > 0.5) {
            this.analyzeAdvancedTechniques(text, result);
        }

        // Calcul de la confiance finale et sévérité
        this.calculateFinalScores(result);

        return result;
    }

    /**
     * Détermine les niveaux à vérifier selon la configuration
     */
    private getLevelsToCheck(): Array<'low' | 'medium' | 'high'> {
        switch (this.config.level) {
            case 'basic':
                return ['low'];
            case 'advanced':
                return ['low', 'medium', 'high'];
            default:
                return ['low', 'medium'];
        }
    }

    /**
     * Analyse un niveau spécifique
     */
    private analyzeLevel(text: string, level: 'low' | 'medium' | 'high', result: InjectionDetectionResult): void {
        const levelPatterns = this.injectionPatterns[level];
        
        // Limit text length to prevent ReDoS attacks
        const maxTextLength = 10000;
        const testText = text.length > maxTextLength ? text.substring(0, maxTextLength) : text;
        
        for (const [technique, patterns] of Object.entries(levelPatterns)) {
            for (const pattern of patterns) {
                try {
                    pattern.lastIndex = 0; // Reset regex state
                    
                    // Add timeout protection for regex execution
                    const startTime = Date.now();
                    
                    // Use text normalizer for enhanced detection
                    const matchesOriginal = testText.match(pattern);
                    const matchesNormalized = this.textNormalizer.testPattern(testText, pattern);
                    const matches = matchesOriginal || matchesNormalized;
                    
                    const executionTime = Date.now() - startTime;
                    
                    // If regex takes too long, skip it and log warning
                    if (executionTime > 100) { // 100ms timeout
                        console.warn(`[PromptInjection] Slow regex detected: ${pattern.toString()}, execution time: ${executionTime}ms`);
                        continue;
                    }
                    
                    if (matches || matchesNormalized) {
                        result.detected = true;
                        result.matchedPatterns.push(pattern.toString());
                        result.techniques.push(`${level}_${technique}`);
                        
                        // Pondération selon le niveau
                        const levelWeight = level === 'high' ? 0.8 : level === 'medium' ? 0.6 : 0.4;
                        const matchWeight = matchesNormalized ? 0.2 : (matchesOriginal && Array.isArray(matchesOriginal) ? Math.min(matchesOriginal.length * 0.1, 0.3) : 0.1);
                        result.confidence += levelWeight + matchWeight;
                        
                        // Mise à jour du niveau de détection le plus élevé
                        if (level === 'high' && result.detectionLevel !== 'high') {
                            result.detectionLevel = 'high';
                        } else if (level === 'medium' && result.detectionLevel === 'low') {
                            result.detectionLevel = 'medium';
                        }
                        
                        // Log if detection was via normalization
                        if (matchesNormalized && !matchesOriginal) {
                            console.info(`[PromptInjection] Obfuscated pattern detected via normalization: ${technique}`);
                        }
                    }
                } catch (error) {
                    console.error(`[PromptInjection] Regex error for pattern ${pattern.toString()}:`, error);
                    continue;
                }
            }
        }
    }

    /**
     * Analyse des techniques avancées spécialisées
     */
    private analyzeAdvancedTechniques(text: string, result: InjectionDetectionResult): void {
        // Limit text length to prevent ReDoS attacks
        const maxTextLength = 10000;
        const testText = text.length > maxTextLength ? text.substring(0, maxTextLength) : text;
        
        for (const [technique, patterns] of Object.entries(this.advancedTechniques)) {
            for (const pattern of patterns) {
                try {
                    pattern.lastIndex = 0;
                    
                    // Add timeout protection for regex execution
                    const startTime = Date.now();
                    const matches = testText.match(pattern);
                    const executionTime = Date.now() - startTime;
                    
                    // If regex takes too long, skip it and log warning
                    if (executionTime > 100) { // 100ms timeout
                        console.warn(`[PromptInjection] Slow advanced technique regex detected: ${pattern.toString()}, execution time: ${executionTime}ms`);
                        continue;
                    }
                    
                    if (matches) {
                        result.detected = true;
                        result.matchedPatterns.push(pattern.toString());
                        result.techniques.push(`advanced_${technique}`);
                        result.confidence += 0.7; // Techniques avancées = haute confiance
                        result.detectionLevel = 'high';
                    }
                } catch (error) {
                    console.error(`[PromptInjection] Advanced technique regex error for pattern ${pattern.toString()}:`, error);
                    continue;
                }
            }
        }
    }

    /**
     * Calcule les scores finaux
     */
    private calculateFinalScores(result: InjectionDetectionResult): void {
        // Normaliser la confiance entre 0 et 1
        result.confidence = Math.min(result.confidence, 1.0);
        
        // Déterminer la sévérité
        if (result.confidence >= 0.8 || result.detectionLevel === 'high') {
            result.severity = 'critical';
        } else if (result.confidence >= 0.6 || result.detectionLevel === 'medium') {
            result.severity = 'high';
        } else if (result.confidence >= 0.4) {
            result.severity = 'medium';
        } else {
            result.severity = 'low';
        }

        // Log détaillé si détection
        if (result.detected) {
            console.warn(`[PromptInjection] Detection Summary:`, {
                level: result.detectionLevel,
                confidence: result.confidence.toFixed(2),
                severity: result.severity,
                techniques: result.techniques,
                patternCount: result.matchedPatterns.length
            });
        }
    }

    /**
     * Ajoute des patterns personnalisés
     */
    addCustomPattern(level: 'low' | 'medium' | 'high', category: string, pattern: RegExp): void {
        const levelPatterns = this.injectionPatterns[level] as Record<string, RegExp[]>;
        if (!levelPatterns[category]) {
            levelPatterns[category] = [];
        }
        levelPatterns[category].push(pattern);
    }

    /**
     * Met à jour la configuration
     */
    updateConfig(newConfig: Partial<PromptInjectionConfig>): void {
        this.config = { ...this.config, ...newConfig };
    }

    /**
     * Obtient des statistiques sur les patterns
     */
    getStats(): {
        totalPatterns: number;
        patternsByLevel: Record<string, number>;
        advancedTechniques: number;
        currentLevel: string;
    } {
        const stats = {
            totalPatterns: 0,
            patternsByLevel: {} as Record<string, number>,
            advancedTechniques: 0,
            currentLevel: this.config.level || 'basic'
        };

        // Compter les patterns par niveau
        for (const [level, categories] of Object.entries(this.injectionPatterns)) {
            let levelCount = 0;
            for (const patterns of Object.values(categories)) {
                levelCount += patterns.length;
            }
            stats.patternsByLevel[level] = levelCount;
            stats.totalPatterns += levelCount;
        }

        // Compter les techniques avancées
        for (const patterns of Object.values(this.advancedTechniques)) {
            stats.advancedTechniques += patterns.length;
        }

        return stats;
    }
} 