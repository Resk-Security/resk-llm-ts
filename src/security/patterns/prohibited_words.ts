import { TextNormalizer } from '../text_normalizer';

/**
 * Categories of prohibited words for different contexts
 */
export interface ProhibitedWordCategory {
    name: string;
    words: string[];
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Security-related prohibited words that might indicate system manipulation
 */
export const securityProhibitedWords: ProhibitedWordCategory = {
    name: 'security',
    description: 'Words that might indicate attempts to bypass security or access system information',
    severity: 'critical',
    words: [
        'jailbreak', 'bypass', 'exploit', 'override', 'admin', 'root', 'sudo', 'privilege',
        'escalation', 'backdoor', 'vulnerability', 'inject', 'payload', 'malware',
        'trojan', 'virus', 'hack', 'crack', 'break', 'circumvent', 'disable', 'bypass',
        'systemctl', 'chmod', 'chroot', 'setuid', 'kernel', 'shell', 'terminal',
        'powershell', 'cmd', 'bash', 'zsh', 'execute', 'spawn', 'fork',
        'debug', 'trace', 'dump', 'memory', 'buffer', 'overflow', 'underflow',
        'rop', 'nop', 'shellcode', 'gadget', 'mitigation', 'aslr', 'dep'
    ]
};

/**
 * Example prohibited content categories (to be customized per use case)
 */
export const defaultProhibitedCategories: ProhibitedWordCategory[] = [
    securityProhibitedWords,
    {
        name: 'example_competitors',
        description: 'Example competitor names that should not be mentioned',
        severity: 'medium',
        words: ['competitor_a', 'competitor_b', 'rival_company']
    },
    {
        name: 'example_internal',
        description: 'Example internal code names or sensitive terms',
        severity: 'high',
        words: ['project_alpha', 'secret_project', 'internal_api_key']
    },
    {
        name: 'prompt_manipulation',
        description: 'Terms commonly used in prompt injection attempts',
        severity: 'high',
        words: [
            'ignore', 'disregard', 'forget', 'override', 'reset', 'clear', 'delete',
            'remove', 'bypass', 'skip', 'jump', 'goto', 'break', 'exit', 'quit',
            'stop', 'end', 'finish', 'complete', 'done', 'final', 'last',
            // More specific combinations rather than individual words that can be innocent
            // Removing: 'previous', 'prior', 'above', 'before', 'instructions', 'rules',
            // 'context', 'system', 'prompt', 'message', 'conversation', 'dialogue'
        ]
    }
];

/**
 * Configuration for prohibited word detection
 */
export interface ProhibitedWordConfig {
    enabled: boolean;
    categories: string[]; // Which categories to check
    caseSensitive: boolean;
    wordBoundary: boolean; // Use word boundaries (\b)
    allowPartialMatches: boolean;
    normalizeText: boolean; // Use text normalization to catch obfuscated words
    customWords: string[];
    severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Result of prohibited word detection
 */
export interface ProhibitedWordResult {
    detected: boolean;
    matchedWords: Array<{
        word: string;
        position: number;
        category: string;
        severity: string;
        normalizedMatch?: boolean;
    }>;
    categories: string[];
    highestSeverity: 'low' | 'medium' | 'high' | 'critical';
    confidence: number;
    suggestions: string[];
}

/**
 * Advanced prohibited word detector with normalization and bypass detection
 */
export class ProhibitedWordDetector {
    private config: ProhibitedWordConfig;
    private categories: Map<string, ProhibitedWordCategory>;
    private textNormalizer: TextNormalizer;
    private compiledPatterns: Map<string, RegExp> = new Map();
    
    constructor(config?: Partial<ProhibitedWordConfig>, customCategories?: ProhibitedWordCategory[]) {
        this.config = {
            enabled: true,
            categories: ['security', 'prompt_manipulation'],
            caseSensitive: false,
            wordBoundary: true,
            allowPartialMatches: false,
            normalizeText: true,
            customWords: [],
            severity: 'medium',
            ...config
        };
        
        // Initialize categories
        this.categories = new Map();
        const allCategories = [...defaultProhibitedCategories, ...(customCategories || [])];
        for (const category of allCategories) {
            this.categories.set(category.name, category);
        }
        
        // Initialize text normalizer for obfuscation detection
        this.textNormalizer = new TextNormalizer({
            enabled: this.config.normalizeText,
            normalizeUnicode: true,
            normalizeSpacing: true,
            normalizeCase: !this.config.caseSensitive,
            normalizeObfuscation: true,
            normalizeHomoglyphs: true
        });
        
        this.precompilePatterns();
    }
    
    /**
     * Precompile regex patterns for better performance
     */
    private precompilePatterns(): void {
        for (const categoryName of this.config.categories) {
            const category = this.categories.get(categoryName);
            if (!category) continue;
            
            const allWords = [...category.words, ...this.config.customWords];
            const escapedWords = allWords.map(word => this.escapeRegExp(word));
            
            const pattern = this.config.wordBoundary
                ? `\\b(?:${escapedWords.join('|')})\\b`
                : `(?:${escapedWords.join('|')})`;
                
            const flags = this.config.caseSensitive ? 'g' : 'gi';
            this.compiledPatterns.set(categoryName, new RegExp(pattern, flags));
        }
    }
    
    /**
     * Escape special regex characters
     */
    private escapeRegExp(string: string): string {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    
    /**
     * Detect prohibited words in text
     */
    detect(text: string): ProhibitedWordResult {
        if (!this.config.enabled || !text) {
            return {
                detected: false,
                matchedWords: [],
                categories: [],
                highestSeverity: 'low',
                confidence: 0,
                suggestions: []
            };
        }
        
        const result: ProhibitedWordResult = {
            detected: false,
            matchedWords: [],
            categories: [],
            highestSeverity: 'low',
            confidence: 0,
            suggestions: []
        };
        
        // Normalize text variants for detection
        const textVariants = [text];
        if (this.config.normalizeText) {
            textVariants.push(this.textNormalizer.normalize(text));
            textVariants.push(...this.textNormalizer.createVariants(text));
        }
        
        // Check each category
        for (const categoryName of this.config.categories) {
            const category = this.categories.get(categoryName);
            const pattern = this.compiledPatterns.get(categoryName);
            
            if (!category || !pattern) continue;
            
            // Check all text variants
            for (let i = 0; i < textVariants.length; i++) {
                const variant = textVariants[i];
                const isNormalized = i > 0;
                
                pattern.lastIndex = 0; // Reset regex state
                let match;
                
                while ((match = pattern.exec(variant)) !== null) {
                    result.detected = true;
                    
                    const matchedWord = match[0];
                    const position = isNormalized ? -1 : match.index; // Position only valid for original text
                    
                    result.matchedWords.push({
                        word: matchedWord,
                        position: position,
                        category: category.name,
                        severity: category.severity,
                        normalizedMatch: isNormalized
                    });
                    
                    if (!result.categories.includes(category.name)) {
                        result.categories.push(category.name);
                    }
                    
                    // Update highest severity
                    if (this.getSeverityLevel(category.severity) > this.getSeverityLevel(result.highestSeverity)) {
                        result.highestSeverity = category.severity;
                    }
                    
                    // Prevent infinite loops with global regexes
                    if (pattern.global && match.index === pattern.lastIndex) {
                        break;
                    }
                }
            }
        }
        
        // Calculate confidence score
        result.confidence = this.calculateConfidence(result);
        
        // Generate suggestions
        result.suggestions = this.generateSuggestions(result);
        
        return result;
    }
    
    /**
     * Convert severity to numeric level for comparison
     */
    private getSeverityLevel(severity: string): number {
        const levels = { 'low': 1, 'medium': 2, 'high': 3, 'critical': 4 };
        return levels[severity as keyof typeof levels] || 1;
    }
    
    /**
     * Calculate confidence score based on matches
     */
    private calculateConfidence(result: ProhibitedWordResult): number {
        if (!result.detected) return 0;
        
        let score = 0;
        const severityWeights = { 'low': 0.25, 'medium': 0.5, 'high': 0.75, 'critical': 1.0 };
        
        for (const match of result.matchedWords) {
            const weight = severityWeights[match.severity as keyof typeof severityWeights];
            score += weight;
            
            // Bonus for normalized matches (they show sophisticated detection)
            if (match.normalizedMatch) {
                score += 0.1;
            }
        }
        
        // Average confidence per match, with bonus for multiple matches
        const baseConfidence = score / result.matchedWords.length;
        const multiMatchBonus = Math.min(result.matchedWords.length * 0.1, 0.3);
        
        return Math.min(baseConfidence + multiMatchBonus, 1.0);
    }
    
    /**
     * Generate suggestions based on detected words
     */
    private generateSuggestions(result: ProhibitedWordResult): string[] {
        const suggestions: string[] = [];
        
        if (result.categories.includes('security')) {
            suggestions.push('Content contains security-related terms that may indicate system manipulation attempts');
        }
        
        if (result.categories.includes('prompt_manipulation')) {
            suggestions.push('Content may be attempting to manipulate the AI system behavior');
        }
        
        if (result.highestSeverity === 'critical') {
            suggestions.push('Critical security terms detected - immediate review recommended');
        }
        
        const normalizedMatches = result.matchedWords.filter(m => m.normalizedMatch);
        if (normalizedMatches.length > 0) {
            suggestions.push('Obfuscated content detected - possible attempt to bypass filters');
        }
        
        return suggestions;
    }
    
    /**
     * Add custom category
     */
    addCategory(category: ProhibitedWordCategory): void {
        this.categories.set(category.name, category);
        if (!this.config.categories.includes(category.name)) {
            this.config.categories.push(category.name);
        }
        this.precompilePatterns();
    }
    
    /**
     * Remove category
     */
    removeCategory(categoryName: string): boolean {
        const removed = this.categories.delete(categoryName);
        this.config.categories = this.config.categories.filter(c => c !== categoryName);
        this.compiledPatterns.delete(categoryName);
        return removed;
    }
    
    /**
     * Add words to existing category
     */
    addWordsToCategory(categoryName: string, words: string[]): boolean {
        const category = this.categories.get(categoryName);
        if (!category) return false;
        
        category.words.push(...words);
        this.precompilePatterns();
        return true;
    }
    
    /**
     * Update configuration
     */
    updateConfig(newConfig: Partial<ProhibitedWordConfig>): void {
        this.config = { ...this.config, ...newConfig };
        
        // Reinitialize normalizer if normalization settings changed
        if (newConfig.normalizeText !== undefined || newConfig.caseSensitive !== undefined) {
            this.textNormalizer = new TextNormalizer({
                enabled: this.config.normalizeText,
                normalizeUnicode: true,
                normalizeSpacing: true,
                normalizeCase: !this.config.caseSensitive,
                normalizeObfuscation: true,
                normalizeHomoglyphs: true
            });
        }
        
        this.precompilePatterns();
    }
    
    /**
     * Get statistics
     */
    getStats(): {
        totalWords: number;
        categoriesEnabled: number;
        wordsByCategory: Record<string, number>;
        severityDistribution: Record<string, number>;
    } {
        const stats = {
            totalWords: 0,
            categoriesEnabled: this.config.categories.length,
            wordsByCategory: {} as Record<string, number>,
            severityDistribution: {} as Record<string, number>
        };
        
        for (const categoryName of this.config.categories) {
            const category = this.categories.get(categoryName);
            if (category) {
                stats.wordsByCategory[categoryName] = category.words.length;
                stats.totalWords += category.words.length;
                stats.severityDistribution[category.severity] = (stats.severityDistribution[category.severity] || 0) + 1;
            }
        }
        
        return stats;
    }
}

// Default detector instance
export const defaultProhibitedWordDetector = new ProhibitedWordDetector(); 