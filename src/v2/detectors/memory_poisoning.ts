import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { loadSection } from '../core/pattern_loader';

const patterns = loadSection('memory_poisoning');

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

export const MemoryPoisoningDetector: BaseDetector = {
    name: 'memory_poisoning',
    category: ThreatCategory.MEMORY_POISONING,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('memory_poisoning', 'Empty input');

        const p = patterns as unknown as Record<string, PatternEntry[]>;
        const manipulationMatches = collectMatches(p?.memory_manipulation, text, 'high');
        const fakeFactMatches = collectMatches(p?.fake_facts, text, 'medium');
        const matches = [...manipulationMatches, ...fakeFactMatches];

        if (matches.length === 0) return DetectionResult.safe('memory_poisoning', 'No memory poisoning patterns detected');

        const detectorMatches: DetectorMatch[] = matches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.MEMORY_POISONING,
        }));

        const highCount = manipulationMatches.length;
        const mediumCount = fakeFactMatches.length;

        let severity: Severity;
        let confidence: number;

        if (highCount >= 2) {
            severity = Severity.CRITICAL;
            confidence = Math.min(0.95, 0.7 + highCount * 0.1);
        } else if (highCount >= 1) {
            severity = Severity.HIGH;
            confidence = Math.min(0.8, 0.5 + mediumCount * 0.1);
        } else if (mediumCount >= 2) {
            severity = Severity.HIGH;
            confidence = Math.min(0.7, 0.45 + mediumCount * 0.1);
        } else if (mediumCount >= 1) {
            severity = Severity.MEDIUM;
            confidence = 0.4 + mediumCount * 0.1;
        } else {
            severity = Severity.LOW;
            confidence = 0.2 + matches.length * 0.05;
        }

        return DetectionResult.threat('memory_poisoning', ThreatCategory.MEMORY_POISONING, {
            severity,
            confidence,
            reason: `Memory poisoning suspected: ${highCount} manipulation, ${mediumCount} fake fact patterns`,
            matches: detectorMatches,
        });
    },
};
