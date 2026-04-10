const HTML_RE = /<(script|style|iframe|object|embed|link|meta)[^>]*>[\s\S]*?<\/\1>|<script[^>]*>[\s\S]*?<\/script[\s\S]*?>|<!--[\s\S]*?-->/gi;
const ZERO_WIDTH_RE = /[\u200b\u200c\u200d\ufeff]{3,}/g;
const BASE64_URI_RE = /data\s*:\s*(?:text|image|application)\/[^;]+;base64,[A-Za-z0-9+/]+=*/g;
const SPECIAL_TOKEN_RE = /<\|endofprompt\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|<\/system>|<\/prompt>/gi;

export class InputSanitizer {
    private _modified = false;
    private _removals: string[] = [];
    sanitize(text: string): string {
        let r = text; this._modified = false; this._removals = [];
        for (const [re, label] of [[HTML_RE,'HTML'],[ZERO_WIDTH_RE,'ZWC'],[BASE64_URI_RE,'dataURI'],[SPECIAL_TOKEN_RE,'token']] as [RegExp,string][]) {
            const c = r.replace(re, ''); if (c !== r) { this._modified = true; this._removals.push(label); r = c; }
        }
        return r.replace(/ {2,}/g,' ').replace(/\t+/g,' ').trim();
    }
    get wasModified(): boolean { return this._modified; }
    get removals(): string[] { return [...this._removals]; }
}
