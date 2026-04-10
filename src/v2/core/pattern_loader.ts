import * as fs from 'fs';
import * as path from 'path';

interface PatternEntry { name: string; pattern: string; description: string; }
interface PatternSection {
    enabled?: boolean;
    high?: PatternEntry[];
    medium?: PatternEntry[];
    low?: PatternEntry[];
    [key: string]: unknown;
}

interface PatternsFile {
    [key: string]: unknown;
}

let _cache: PatternsFile | null = null;

export function loadPatternConfig(): PatternsFile {
    if (_cache) return _cache;
    const configPath = path.join(__dirname, '..', 'config', 'patterns.json');
    if (fs.existsSync(configPath)) {
        try {
            _cache = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
        } catch { /* ignore */ }
    }
    return _cache ?? {};
}

export function loadSection(name: string): PatternSection | null {
    const config = loadPatternConfig();
    const section = config[name] as PatternSection | undefined;
    return section ?? null;
}

export function compilePatterns(section: PatternSection | null, text: string): Array<{ name: string; match: string; level: string }> {
    if (!section) return [];
    const results: Array<{ name: string; match: string; level: string }> = [];
    for (const level of ['high', 'medium', 'low']) {
        const entries = (section as Record<string, undefined>)[level] as PatternEntry[] | undefined;
        if (!entries) continue;
        for (const entry of entries) {
            try {
                const re = new RegExp(entry.pattern, 'i');
                const m = re.exec(text);
                if (m) {
                    results.push({ name: entry.name, match: m[0], level });
                }
            } catch { /* skip bad patterns */ }
        }
    }
    return results;
}

export function getPatternValue(section: string, key: string): unknown {
    const config = loadPatternConfig();
    const sec = config[section] as Record<string, unknown> | undefined;
    return sec?.[key];
}
