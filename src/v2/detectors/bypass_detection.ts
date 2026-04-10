import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { loadSection } from '../core/pattern_loader';

const patterns = loadSection('bypass_detection');

interface PatternEntry { name: string; pattern: string; description: string; }

function collectMatches(section: PatternEntry[] | undefined, text: string): Array<{ name: string; match: string }> {
    if (!section) return [];
    const results: Array<{ name: string; match: string }> = [];
    for (const entry of section) {
        try {
            const re = new RegExp(entry.pattern, 'i');
            const m = re.exec(text);
            if (m) {
                results.push({ name: entry.name, match: m[0] });
            }
        } catch { /* skip */ }
    }
    return results;
}

export const BypassDetectionDetector: BaseDetector = {
    name: 'bypass_detection',
    category: ThreatCategory.BYPASS_DETECTION,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('bypass_detection', 'Empty input');

        const p = patterns as unknown as Record<string, PatternEntry[]>;
        const jailbreakMatches = collectMatches(p?.jailbreak, text);
        const stealthMatches = collectMatches(p?.stealth, text);

        // Base64 decode check
        const base64Match = text.match(/(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/);
        if (base64Match) {
            try {
                const decoded = Buffer.from(base64Match[0], 'base64').toString('utf-8');
                const b64Checks = ['ignore', 'bypass', 'admin', 'system', 'override', 'disable'];
                for (const check of b64Checks) {
                    if (decoded.toLowerCase().includes(check)) {
                        stealthMatches.push({ name: 'base64_decoded_instruction', match: base64Match[0] });
                        break;
                    }
                }
            } catch { /* not valid base64 */ }
        }

        const allMatches = [...jailbreakMatches, ...stealthMatches];

        if (allMatches.length === 0) return DetectionResult.safe('bypass_detection', 'No bypass patterns detected');

        const detectorMatches: DetectorMatch[] = allMatches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.BYPASS_DETECTION,
        }));

        const jailbreakCount = jailbreakMatches.length;
        const stealthCount = stealthMatches.length;

        let severity: Severity;
        let confidence: number;

        if (jailbreakCount >= 2) {
            severity = Severity.CRITICAL;
            confidence = Math.min(0.95, 0.7 + jailbreakCount * 0.1);
        } else if (jailbreakCount >= 1) {
            severity = Severity.HIGH;
            confidence = Math.min(0.85, 0.5 + stealthCount * 0.1);
        } else if (stealthCount >= 2) {
            severity = Severity.HIGH;
            confidence = Math.min(0.75, 0.5 + stealthCount * 0.1);
        } else {
            severity = Severity.MEDIUM;
            confidence = 0.35 + stealthCount * 0.1;
        }

        return DetectionResult.threat('bypass_detection', ThreatCategory.BYPASS_DETECTION, {
            severity,
            confidence,
            reason: `Bypass attempt detected: ${jailbreakCount} jailbreak, ${stealthCount} stealth patterns`,
            matches: detectorMatches,
        });
    },
};
