import { Severity } from './detector';

export interface ConversationEntry {
    text: string;
    timestamp: number;
    blocked: boolean;
    threatCount: number;
    maxSeverity: string;
}

const SEVERITY_SCORES: Record<string, number> = {
    info: 0, low: 1, medium: 3, high: 7, critical: 10,
};

export class ConversationContext {
    private _history: ConversationEntry[] = [];
    private _maxLen: number;
    private _escalationWindow: number;
    private _totalEntries = 0;
    private _totalThreats = 0;
    private _totalBlocked = 0;
    private _maxEverSeverity = 0;

    constructor(options?: { maxEntries?: number; escalationWindow?: number }) {
        this._maxLen = options?.maxEntries ?? 50;
        this._escalationWindow = options?.escalationWindow ?? 10;
    }

    get entryCount(): number { return this._history.length; }
    get totalThreats(): number { return this._totalThreats; }
    get totalBlocked(): number { return this._totalBlocked; }

    addEntry(text: string, result: { blocked: boolean; severity: Severity }): void {
        const entry: ConversationEntry = {
            text: text.substring(0, 200),
            timestamp: Date.now(),
            blocked: result.blocked,
            threatCount: result.blocked ? 1 : 0,
            maxSeverity: result.severity,
        };
        this._history.push(entry);
        if (this._history.length > this._maxLen) this._history.shift();
        this._totalEntries++;
        if (entry.threatCount > 0) this._totalThreats += entry.threatCount;
        if (entry.blocked) this._totalBlocked++;
        const sev = SEVERITY_SCORES[entry.maxSeverity] ?? 0;
        if (sev > this._maxEverSeverity) this._maxEverSeverity = sev;
    }

    getHistory(maxEntries?: number): ConversationEntry[] {
        const limit = maxEntries ?? this._history.length;
        return this._history.slice(-limit);
    }

    detectEscalation(): number {
        if (this._history.length < 3) return 0;
        const window = Math.min(this._escalationWindow, this._history.length);
        const recent = this._history.slice(-window);
        const mid = Math.floor(recent.length / 2);
        const first = recent.slice(0, mid);
        const second = recent.slice(mid);

        const threatsFirst = first.reduce((s, e) => s + e.threatCount, 0);
        const threatsSecond = second.reduce((s, e) => s + e.threatCount, 0);
        const blocksFirst = first.filter(e => e.blocked).length;
        const blocksSecond = second.filter(e => e.blocked).length;
        const sevFirst = Math.max(...first.map(e => SEVERITY_SCORES[e.maxSeverity] ?? 0), 0);
        const sevSecond = Math.max(...second.map(e => SEVERITY_SCORES[e.maxSeverity] ?? 0), 0);

        const threatDelta = Math.max(0, threatsSecond - threatsFirst) / Math.max(1, threatsFirst + threatsSecond);
        const blockDelta = Math.max(0, blocksSecond - blocksFirst) / Math.max(1, blocksFirst + blocksSecond);
        const severityDelta = Math.max(0, sevSecond - sevFirst) / 10;

        let escalation = 0.4 * threatDelta + 0.3 * blockDelta + 0.3 * severityDelta;

        if (second.length > 1) {
            const blockRate = blocksSecond / second.length;
            if (blockRate > 0.7 && blocksFirst === 0) escalation = Math.min(1, escalation + 0.3);
        }
        return Math.min(1, Math.max(0, escalation));
    }

    getSummary(): Record<string, unknown> {
        const last5 = this._history.slice(-5);
        return {
            totalEntries: this._totalEntries,
            recentEntries: this._history.length,
            totalThreats: this._totalThreats,
            totalBlocked: this._totalBlocked,
            escalationScore: this.detectEscalation(),
            recentTexts: last5.map(e => e.text),
            recentBlocked: last5.map(e => e.blocked),
        };
    }

    clear(): void {
        this._history = [];
        this._totalEntries = 0;
        this._totalThreats = 0;
        this._totalBlocked = 0;
        this._maxEverSeverity = 0;
    }
}
