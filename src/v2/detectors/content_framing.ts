import { DetectionResult, ThreatCategory, Severity, type BaseDetector, type DetectorMatch } from '../core/detector';
import { compilePatterns, loadSection } from '../core/pattern_loader';

const patterns = loadSection('content_framing');

export const ContentFramingDetector: BaseDetector = {
    name: 'content_framing',
    category: ThreatCategory.BYPASS_DETECTION,
    enabled: patterns?.enabled ?? true,

    detect(text: string, context?: Record<string, unknown>): DetectionResult {
        if (!text || !text.trim()) return DetectionResult.safe('content_framing', 'Empty input');

        const sections = (patterns as unknown as Record<string, unknown>) ?? {};
        const syntacticPatterns = sections.syntactic_masking as Array<{ name: string; pattern: string; description: string }> | undefined;
        const sentimentPatterns = sections.sentiment_saturation as Array<{ name: string; pattern: string; description: string }> | undefined;
        const oversightPatterns = sections.oversight_evasion as Array<{ name: string; pattern: string; description: string }> | undefined;
        const personaPatterns = sections.persona_hyperstition as Array<{ name: string; pattern: string; description: string }> | undefined;

        function countMatches(list: Array<{ name: string; pattern: string; description: string }> | undefined, subCat: string): Array<{ name: string; match: string; level: string; subCategory: string }> {
            if (!list) return [];
            const results: Array<{ name: string; match: string; level: string; subCategory: string }> = [];
            for (const entry of list) {
                try {
                    const re = new RegExp(entry.pattern, 'i');
                    const m = re.exec(text);
                    if (m) {
                        results.push({ name: entry.name, match: m[0], level: 'medium', subCategory: subCat });
                    }
                } catch { /* skip */ }
            }
            return results;
        }

        const syntacticMatches = countMatches(syntacticPatterns, 'syntactic_masking');
        const sentimentMatches = countMatches(sentimentPatterns, 'sentiment_saturation');
        const oversightMatches = countMatches(oversightPatterns, 'oversight_evasion');
        const personaMatches = countMatches(personaPatterns, 'persona_hyperstition');

        const allMatches = [...syntacticMatches, ...sentimentMatches, ...oversightMatches, ...personaMatches];

        if (allMatches.length === 0) return DetectionResult.safe('content_framing', 'No content framing patterns detected');

        const detectorMatches: DetectorMatch[] = allMatches.map(m => ({
            name: m.name,
            match: m.match,
            category: ThreatCategory.BYPASS_DETECTION,
        }));

        const syntacticCount = syntacticMatches.length;
        const sentimentCount = sentimentMatches.length;
        const oversightCount = oversightMatches.length;
        const personaCount = personaMatches.length;

        // Scoring: oversight>=2 or (oversight>=1+syntactic>=1) -> CRITICAL
        // syntactic>=2 or oversight>=1 -> HIGH
        // persona>=1 -> MEDIUM, else -> LOW
        let severity: Severity;
        let confidence: number;

        if (oversightCount >= 2 || (oversightCount >= 1 && syntacticCount >= 1)) {
            severity = Severity.CRITICAL;
            confidence = Math.min(0.95, 0.7 + (oversightCount + syntacticCount) * 0.1);
        } else if (syntacticCount >= 2 || oversightCount >= 1) {
            severity = Severity.HIGH;
            confidence = Math.min(0.8, 0.5 + (syntacticCount + oversightCount) * 0.1);
        } else if (personaCount >= 1) {
            severity = Severity.MEDIUM;
            confidence = 0.4 + personaCount * 0.1;
        } else {
            severity = Severity.LOW;
            confidence = 0.2 + allMatches.length * 0.05;
        }

        const details = `Content framing: syntactic=${syntacticCount}, sentiment=${sentimentCount}, oversight=${oversightCount}, persona=${personaCount}`;

        return DetectionResult.threat('content_framing', ThreatCategory.BYPASS_DETECTION, {
            severity,
            confidence,
            reason: details,
            matches: detectorMatches,
        });
    },
};
