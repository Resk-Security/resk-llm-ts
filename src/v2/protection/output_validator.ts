export interface ValidationResult { isSafe: boolean; issues: Array<{ type: string; category: string; match: string }>; }
const PII = [[/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,'email','pii'],[/\b(?:\d{4}[-\s]?){3}\d{4}\b/g,'cc','pii'],[/\b(?:password|pwd|apiKey|api_key|token|secret_key)\s*[:=]\s*\S{8,}/g,'cred','pii']] as [RegExp,string,string][];
const INJ = [[/<script|javascript:|<iframe|on\w+\s*=/gi,'xss','inj'],[/\bUNION\s+SELECT\b/gi,'sqli','inj']] as [RegExp,string,string][];
export class OutputValidator {
    validate(text: string): ValidationResult {
        const issues: ValidationResult['issues'] = [];
        for (const [re,type,cat] of [...PII,...INJ]) { re.lastIndex=0; const m=re.exec(text); if(m) issues.push({type,category:cat,match:m[0].substring(0,80)}); }
        return { isSafe: issues.length===0, issues };
    }
}
