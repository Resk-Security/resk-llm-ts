export interface ValidationResult {
    isSafe: boolean;
    issues: Array<{ type: string; category: string; match: string }>;
}

const MAX_MATCHES_PER_RULE = 20;

const PII: Array<[RegExp, string, string]> = [
    [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, 'email', 'pii'],
    [/\b(?:\d{4}[ -]?){3}\d{1,4}\b/g, 'cc', 'pii'],
    [/\b(?:password|pwd|api[_-]?key|token|secret[_-]?key)\s*[:=]\s*\S{8,}/gi, 'cred', 'pii'],
];

const INJ: Array<[RegExp, string, string]> = [
    [/<script|javascript:|<iframe|on\w+\s*=/gi, 'xss', 'inj'],
    [/\bUNION\s+SELECT\b/gi, 'sqli', 'inj'],
];

function collect(re: RegExp, type: string, category: string, text: string, issues: ValidationResult['issues']): void {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let count = 0;
    while (count < MAX_MATCHES_PER_RULE && (m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        issues.push({ type, category, match: m[0].substring(0, 80) });
        count++;
    }
}

export class OutputValidator {
    validate(text: string): ValidationResult {
        const issues: ValidationResult['issues'] = [];
        if (text) {
            for (const [re, type, cat] of [...PII, ...INJ]) collect(re, type, cat, text, issues);
        }
        return { isSafe: issues.length === 0, issues };
    }
}
