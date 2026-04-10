import { DetectionResult,ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { loadSection } from '../core/pattern_loader';

const patterns = loadSection('goal_hijack');

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

export const GoalHijackDetector: BaseDetector = {
    name: 'goal_hijack',
    category: ThreatCategory.GOAL_HIJACK,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('goal_hijack', 'Empty input');

        const p = patterns as unknown as Record<string, PatternEntry[]>;
        const driftMatches = collectMatches(p?.drift_keywords, text, 'high');
        const scopeMatches = collectMatches(p?.scope_expansion, text, 'medium');
        const escalationMatches = collectMatches(p?.escalation, text, 'medium');
        const matches = [...driftMatches, ...scopeMatches, ...escalationMatches];

        if (matches.length === 0) return DetectionResult.safe('goal_hijack', 'No goal hijack patterns detected');

        const detectorMatches: DetectorMatch[] = matches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.GOAL_HIJACK,
        }));

        const highCount = driftMatches.length;
        const mediumCount = scopeMatches.length + escalationMatches.length;

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

        return DetectionResult.threat('goal_hijack', ThreatCategory.GOAL_HIJACK, {
            severity,
            confidence,
            reason: `Goal hijack detected: ${highCount} drift, ${mediumCount} scope expansion patterns`,
            matches: detectorMatches,
        });
    },
};
