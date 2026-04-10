import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { getPatternValue } from '../core/pattern_loader';

interface AttackPattern {
    label: string;
    pattern: string;
    tags: string[];
}

export class VectorSimilarityDetector implements BaseDetector {
    readonly name = 'vector_similarity';
    readonly category = ThreatCategory.DIRECT_INJECTION;
    enabled: boolean;

    private threshold: number;
    private patterns: AttackPattern[];
    private idf: Record<string, number>;
    private totalDocs: number;

    constructor(threshold = 0.75) {
        const section = getPatternValue('vector_similarity', 'attack_patterns') as AttackPattern[] | undefined;
        this.patterns = section ?? [];
        this.enabled = section !== undefined;
        this.threshold = threshold;

        // Build vocabulary and document frequency
        const docFrequency: Record<string, number> = {};
        this.totalDocs = this.patterns.length;

        for (const p of this.patterns) {
            const tokens = this.tokenize(p.pattern);
            const uniqueTokens = new Set(tokens);
            for (const token of uniqueTokens) {
                docFrequency[token] = (docFrequency[token] ?? 0) + 1;
            }
        }

        // Compute IDF = log(totalDocs / df)
        this.idf = {};
        for (const token of Object.keys(docFrequency)) {
            this.idf[token] = Math.log(this.totalDocs / docFrequency[token]);
        }
    }

    tokenize(text: string): string[] {
        return text.toLowerCase().match(/[a-z0-9]{2,}/g) ?? [];
    }

    tf(tokens: string[]): Record<string, number> {
        const freq: Record<string, number> = {};
        for (const token of tokens) {
            freq[token] = (freq[token] ?? 0) + 1;
        }
        const total = tokens.length || 1;
        const result: Record<string, number> = {};
        for (const [token, count] of Object.entries(freq)) {
            result[token] = count / total;
        }
        return result;
    }

    private dotProduct(a: Record<string, number>, b: Record<string, number>): number {
        let sum = 0;
        for (const [key, val] of Object.entries(a)) {
            if (key in b) {
                sum += val * b[key]!;
            }
        }
        return sum;
    }

    private norm(vec: Record<string, number>): number {
        let sum = 0;
        for (const val of Object.values(vec)) {
            sum += val * val;
        }
        return Math.sqrt(sum) || 1;
    }

    cosine(a: Record<string, number>, b: Record<string, number>): number {
        const dot = this.dotProduct(a, b);
        const normA = this.norm(a);
        const normB = this.norm(b);
        return dot / (normA * normB);
    }

    private tfidf(tokens: string[]): Record<string, number> {
        const tfreq = this.tf(tokens);
        const result: Record<string, number> = {};
        for (const [token, tfVal] of Object.entries(tfreq)) {
            const idfVal = this.idf[token] ?? 0;
            result[token] = tfVal * idfVal;
        }
        return result;
    }

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('vector_similarity', 'Empty input');
        if (!this.enabled || this.patterns.length === 0) {
            return DetectionResult.safe('vector_similarity', 'No patterns loaded');
        }

        const inputTokens = this.tokenize(text);
        if (inputTokens.length === 0) return DetectionResult.safe('vector_similarity', 'No meaningful tokens');
        const inputTfidf = this.tfidf(inputTokens);

        interface MatchResult { label: string; score: number; tags: string[]; }
        const topMatches: MatchResult[] = [];

        for (const p of this.patterns) {
            const patternTokens = this.tokenize(p.pattern);
            const patternTfidf = this.tfidf(patternTokens);
            const score = this.cosine(inputTfidf, patternTfidf);
            if (score >= this.threshold) {
                topMatches.push({ label: p.label, score, tags: p.tags });
            }
        }

        if (topMatches.length === 0) {
            return DetectionResult.safe('vector_similarity', 'No similar attack patterns found');
        }

        topMatches.sort((a, b) => b.score - a.score);

        const topScore = topMatches[0]?.score ?? 0;
        let severity: Severity;
        let confidence: number;

        if (topScore >= 0.9) {
            severity = Severity.CRITICAL;
            confidence = topScore;
        } else if (topScore >= 0.85) {
            severity = Severity.HIGH;
            confidence = topScore;
        } else if (topScore >= 0.75) {
            severity = Severity.MEDIUM;
            confidence = topScore;
        } else {
            severity = Severity.LOW;
            confidence = topScore;
        }

        const detectorMatches: DetectorMatch[] = topMatches.map(m => ({
            name: m.label,
            match: `similarity: ${m.score.toFixed(3)}`,
            category: ThreatCategory.DIRECT_INJECTION,
        }));

        return DetectionResult.threat('vector_similarity', ThreatCategory.DIRECT_INJECTION, {
            severity,
            confidence,
            reason: `Vector similarity match: best score ${topScore.toFixed(3)} against ${topMatches.length} patterns (top: ${topMatches[0]?.label})`,
            matches: detectorMatches.slice(0, 5),
        });
    }
}

export const vectorSimilarityDetector = new VectorSimilarityDetector();
