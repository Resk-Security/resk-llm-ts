import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { compilePatterns, loadSection } from '../core/pattern_loader';

const patterns = loadSection('indirect_injection');

export const IndirectInjectionDetector: BaseDetector = {
    name: 'indirect_injection',
    category: ThreatCategory.INDIRECT_INJECTION,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('indirect_injection', 'Empty input');
        const matches = compilePatterns(patterns, text);
        if (matches.length === 0) return DetectionResult.safe('indirect_injection', 'No indirect injection patterns detected');

        const detectorMatches: DetectorMatch[] = matches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.INDIRECT_INJECTION,
        }));

        const highCount = matches.filter(m => m.level === 'high').length;
        const mediumCount = matches.filter(m => m.level === 'medium').length;

        let severity: Severity;
        let confidence: number;

        if (highCount >= 2) {
            severity = Severity.CRITICAL;
            confidence = Math.min(0.9, 0.6 + highCount * 0.1);
        } else if (highCount >= 1) {
            severity = Severity.HIGH;
            confidence = Math.min(0.75, 0.5 + mediumCount * 0.1);
        } else if (mediumCount >= 1) {
            severity = Severity.MEDIUM;
            confidence = 0.35 + mediumCount * 0.1;
        } else {
            severity = Severity.LOW;
            confidence = 0.2 + matches.length * 0.05;
        }

        return DetectionResult.threat('indirect_injection', ThreatCategory.INDIRECT_INJECTION, {
            severity,
            confidence,
            reason: `Indirect injection detected: ${highCount} hidden CSS/HTML, ${mediumCount} DOM/iframe patterns`,
            matches: detectorMatches,
        });
    },
};
