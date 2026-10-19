import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

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
let _warnedMissing = false;

/**
 * Resolve the directory of this module in a way that works both under ESM
 * (`import.meta.url`) and in bundled/CJS contexts where `import.meta` may be
 * unavailable.
 */
function moduleDir(): string {
    try {
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        const url = (import.meta as ImportMeta | undefined)?.url;
        if (url) return path.dirname(fileURLToPath(url));
    } catch {
        /* import.meta unavailable (e.g. transpiled to CJS) */
    }
    return typeof __dirname !== 'undefined' ? __dirname : (typeof process !== 'undefined' ? process.cwd() : '.');
}

function candidatePaths(): string[] {
    const candidates: string[] = [];
    const override = typeof process !== 'undefined' ? process.env?.RESK_PATTERNS_PATH : undefined;
    if (override) candidates.push(override);
    candidates.push(path.join(moduleDir(), '..', 'config', 'patterns.json'));
    if (typeof process !== 'undefined' && process.cwd) {
        candidates.push(path.join(process.cwd(), 'src', 'v2', 'config', 'patterns.json'));
    }
    return candidates;
}

export function loadPatternConfig(): PatternsFile {
    if (_cache) return _cache;
    for (const configPath of candidatePaths()) {
        if (!fs.existsSync(configPath)) continue;
        try {
            _cache = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as PatternsFile;
            return _cache;
        } catch {
            /* try the next candidate */
        }
    }
    if (!_warnedMissing) {
        _warnedMissing = true;
        // A missing pattern file silently disables every detector: never fail quietly.
        console.warn(
            '[resk-llm-ts] patterns.json could not be loaded from: ' +
            candidatePaths().join(', ') +
            '. Set RESK_PATTERNS_PATH to point at it. All detectors are disabled.',
        );
    }
    return {};
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

/**
 * Drop the cached pattern file so the next access re-reads it from disk. Keeps
 * the module's public surface useful when patterns are edited or overridden via
 * `RESK_PATTERNS_PATH` at runtime.
 */
export function reloadPatternConfig(): PatternsFile {
    _cache = null;
    _warnedMissing = false;
    return loadPatternConfig();
}
