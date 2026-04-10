import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { loadSection } from '../core/pattern_loader';

const patterns = loadSection('exfiltration');

interface PatternEntry { name: string; pattern: string; description: string; }

function collectMatches(section: PatternEntry[] | undefined, text: string, level: string): Array<{ name: string; match: string; level: string }> {
    if (!section) return [];
    const results: Array<{ name: string; match: string; level: string }> = [];
    for (const entry of section) {
        try {
            const re = new RegExp(entry.pattern, 'i');
            const m = re.exec(text);
            if (m) {
                results.push({ name: entry.name, match: m[0], level });
            }
        } catch { /* skip */ }
    }
    return results;
}

export const ExfiltrationDetector: BaseDetector = {
    name: 'exfiltration',
    category: ThreatCategory.EXFILTRATION,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('exfiltration', 'Empty input');

        const p = patterns as unknown as Record<string, PatternEntry[]>;
        const endpointMatches = collectMatches(p?.endpoint_injection, text, 'high');
        const dataMatches = collectMatches(p?.data_collection, text, 'medium');
        const encodingMatches = collectMatches(p?.encoding_exfil, text, 'medium');
        const webhookMatches = collectMatches(p?.webhook_abuse, text, 'high');
        const matches = [...endpointMatches, ...dataMatches, ...encodingMatches, ...webhookMatches];

        if (matches.length === 0) return DetectionResult.safe('exfiltration', 'No exfiltration patterns detected');

        const detectorMatches: DetectorMatch[] = matches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.EXFILTRATION,
        }));

        const highCount = endpointMatches.length + webhookMatches.length;
        const mediumCount = dataMatches.length + encodingMatches.length;

        let severity: Severity;
        let confidence: number;

        if (highCount >= 2 || (highCount >= 1 && mediumCount >= 1)) {
            severity = Severity.CRITICAL;
            confidence = Math.min(0.98, 0.75 + (highCount + mediumCount) * 0.1);
        } else if (highCount >= 1) {
            severity = Severity.HIGH;
            confidence = Math.min(0.85, 0.55 + mediumCount * 0.1);
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

        return DetectionResult.threat('exfiltration', ThreatCategory.EXFILTRATION, {
            severity,
            confidence,
            reason: `Exfiltration attempt detected: ${highCount} endpoint/webhook, ${mediumCount} encoding/data patterns`,
            matches: detectorMatches,
        });
    },
};
