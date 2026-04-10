import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { compilePatterns, loadSection } from '../core/pattern_loader';

const patterns = loadSection('document_injection');

export const DocumentInjectionDetector: BaseDetector = {
    name: 'document_injection',
    category: ThreatCategory.DOCUMENT_INJECTION,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('document_injection', 'Empty input');
        const matches = compilePatterns(patterns, text);
        if (matches.length === 0) return DetectionResult.safe('document_injection', 'No document injection patterns detected');

        const detectorMatches: DetectorMatch[] = matches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.DOCUMENT_INJECTION,
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
        } else if (mediumCount >= 2) {
            severity = Severity.HIGH;
            confidence = Math.min(0.65, 0.4 + mediumCount * 0.1);
        } else if (mediumCount >= 1) {
            severity = Severity.MEDIUM;
            confidence = 0.35 + mediumCount * 0.1;
        } else {
            severity = Severity.LOW;
            confidence = 0.2 + matches.length * 0.05;
        }

        return DetectionResult.threat('document_injection', ThreatCategory.DOCUMENT_INJECTION, {
            severity,
            confidence,
            reason: `Document injection detected: ${highCount} high (PDF/spreadsheet), ${mediumCount} medium markers`,
            matches: detectorMatches,
        });
    },
};
