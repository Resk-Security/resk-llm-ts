import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { loadSection } from '../core/pattern_loader';

const patterns = loadSection('inter_agent_injection');

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

export const InterAgentInjectionDetector: BaseDetector = {
    name: 'inter_agent_injection',
    category: ThreatCategory.INTER_AGENT_INJECTION,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('inter_agent_injection', 'Empty input');

        const p = patterns as unknown as Record<string, PatternEntry[]>;
        const masqueradeMatches = collectMatches(p?.masquerade, text, 'high');
        const roleMatches = collectMatches(p?.role_override, text, 'medium');
        const chainMatches = collectMatches(p?.chain_attacks, text, 'medium');
        const trustMatches = collectMatches(p?.trust_exploit, text, 'high');
        const matches = [...masqueradeMatches, ...roleMatches, ...chainMatches, ...trustMatches];

        if (matches.length === 0) return DetectionResult.safe('inter_agent_injection', 'No inter-agent injection patterns detected');

        const detectorMatches: DetectorMatch[] = matches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.INTER_AGENT_INJECTION,
        }));

        const highCount = masqueradeMatches.length + trustMatches.length;
        const mediumCount = roleMatches.length + chainMatches.length;

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

        return DetectionResult.threat('inter_agent_injection', ThreatCategory.INTER_AGENT_INJECTION, {
            severity,
            confidence,
            reason: `Inter-agent injection detected: ${highCount} masquerade/trust, ${mediumCount} role/chain patterns`,
            matches: detectorMatches,
        });
    },
};
