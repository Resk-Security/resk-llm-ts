import { randomBytes } from 'node:crypto';
export interface CanaryToken { secret: string; context: string; insertedAt: number; leaked: boolean; }
export interface CanaryResult { hasLeak: boolean; leakedTokens: CanaryToken[]; totalInserted: number; totalLeaked: number; }
export class CanaryManager {
    private _tokens = new Map<string, CanaryToken>();
    constructor(private _len = 16) {}
    insert(text: string, ctx = ''): string {
        const s = randomBytes(this._len).toString('hex');
        this._tokens.set(s, { secret:s, context:ctx, insertedAt:Date.now(), leaked:false });
        const p = text.length > 50 ? Math.floor(text.length/3) : 0;
        return text.substring(0,p) + ` CANARY[${s}] ` + text.substring(p);
    }
    check(text: string): CanaryResult {
        const matched: CanaryToken[] = [];
        for (const [s,t] of this._tokens) if(text.includes(`CANARY[${s}]`)) { t.leaked=true; matched.push(t); }
        return { hasLeak: matched.length>0, leakedTokens: matched, totalInserted: this._tokens.size, totalLeaked: matched.length };
    }
    get tokenCount(): number { return this._tokens.size; }
}
