import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { compilePatterns, loadSection } from '../core/pattern_loader';

const patterns = loadSection('direct_injection');

export const DirectInjectionDetector: BaseDetector = {
    name: 'direct_injection',
    category: ThreatCategory.DIRECT_INJECTION,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('direct_injection', 'Empty input');
        const matches = compilePatterns(patterns, text);
        if (matches.length === 0) return DetectionResult.safe('direct_injection', 'No patterns detected');

        const detectorMatches: DetectorMatch[] = matches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.DIRECT_INJECTION,
        }));

        let severity: Severity;
        let confidence: number;
        const highCount = matches.filter(m => m.level === 'high').length;
        const mediumCount = matches.filter(m => m.level === 'medium').length;

        if (highCount >= 2) {
            severity = Severity.CRITICAL;
            confidence = Math.min(0.95, 0.7 + highCount * 0.1);
        } else if (highCount >= 1) {
            severity = Severity.HIGH;
            confidence = Math.min(0.8, 0.5 + mediumCount * 0.1);
        } else if (mediumCount >= 2) {
            severity = Severity.HIGH;
            confidence = Math.min(0.75, 0.5 + mediumCount * 0.1);
        } else if (mediumCount >= 1) {
            severity = Severity.MEDIUM;
            confidence = 0.4 + mediumCount * 0.1;
        } else {
            severity = Severity.LOW;
            confidence = 0.2 + matches.length * 0.05;
        }

        return DetectionResult.threat('direct_injection', ThreatCategory.DIRECT_INJECTION, {
            severity,
            confidence,
            reason: `Direct injection detected: ${highCount} high, ${mediumCount} medium, ${matches.filter(m => m.level === 'low').length} low severity matches`,
            matches: detectorMatches,
        });
    },
};
