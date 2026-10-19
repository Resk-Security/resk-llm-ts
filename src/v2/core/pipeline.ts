import { DetectionResult, type BaseDetector, Severity, ThreatCategory } from './detector.js';
import { DEFAULT_CONFIG, type SecurityConfig } from './config.js';
import { InputSanitizer } from '../protection/input_sanitizer.js';

export interface PipelineResult {
    inputText: string;
    results: DetectionResult[];
    blocked: boolean;
    blockReason: string;
    severity: Severity;
    sanitizedText: string;
}

export interface PipelineOptions {
    /** Sanitizer used to build `sanitizedText`. Pass `null` to disable. */
    sanitizer?: InputSanitizer | null;
}

export namespace PipelineResult {
    const SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL];

    export function maxSeverity(results: DetectionResult[]): Severity {
        const threats = results.filter(r => r.isThreat);
        if (threats.length === 0) return Severity.INFO;
        let max = Severity.INFO;
        for (const t of threats) {
            if (SEVERITY_ORDER.indexOf(t.severity) > SEVERITY_ORDER.indexOf(max)) {
                max = t.severity;
            }
        }
        return max;
    }
}

export class SecurityPipeline {
    private _detectors: BaseDetector[] = [];
    private config: Required<SecurityConfig>;
    private _blockedCategories: Set<string>;
    private _sanitizer: InputSanitizer | null;
    private _cache = new Map<string, PipelineResult>();

    constructor(config?: SecurityConfig, options: PipelineOptions = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this._blockedCategories = new Set(this.config.blockCategories);
        this._sanitizer = options.sanitizer === undefined ? new InputSanitizer() : options.sanitizer;
    }

    get detectors(): ReadonlyArray<BaseDetector> {
        return this._detectors;
    }

    add(detector: BaseDetector): this {
        this._detectors.push(detector);
        return this;
    }

    addAll(detectors: ReadonlyArray<BaseDetector>): this {
        for (const d of detectors) this.add(d);
        return this;
    }

    remove(name: string): boolean {
        const before = this._detectors.length;
        this._detectors = this._detectors.filter(d => d.name !== name);
        return this._detectors.length < before;
    }

    clearCache(): void {
        this._cache.clear();
    }

    run(text: string, context?: Record<string, unknown>): PipelineResult {
        // Enforce the size limit *before* any detector (regular expressions) runs.
        if (text.length > this.config.maxInputLength) {
            const reason = `Input length ${text.length} exceeds maxInputLength (${this.config.maxInputLength})`;
            const oversized = DetectionResult.threat('pipeline', ThreatCategory.DIRECT_INJECTION, {
                severity: Severity.HIGH,
                confidence: 1,
                reason,
            });
            return {
                inputText: text,
                results: [oversized],
                blocked: true,
                blockReason: reason,
                severity: Severity.HIGH,
                sanitizedText: '',
            };
        }

        const cacheKey = this.config.enableCaching && (!context || Object.keys(context).length === 0)
            ? text
            : null;
        if (cacheKey !== null) {
            const hit = this._cache.get(cacheKey);
            if (hit) return hit;
        }

        const results = this._runDetectors(text, context);
        const result = this._finalize(text, results);

        if (cacheKey !== null) this._remember(cacheKey, result);
        return result;
    }

    private _runDetectors(text: string, context?: Record<string, unknown>): DetectionResult[] {
        const results: DetectionResult[] = [];
        for (const detector of this._detectors) {
            if (!detector.enabled) continue;
            try {
                results.push(detector.detect(text, context));
            } catch (e) {
                const message = e instanceof Error ? e.message : String(e);
                if (this.config.failOpen) {
                    results.push(DetectionResult.safe(detector.name, `Detector error (fail-open): ${message}`));
                } else {
                    results.push(DetectionResult.threat(detector.name, detector.category, {
                        severity: Severity.HIGH,
                        confidence: 1,
                        reason: `Detector error (fail-closed): ${message}`,
                    }));
                }
            }
        }
        return results;
    }

    private _finalize(text: string, results: DetectionResult[]): PipelineResult {
        const activeThreats = results.filter(
            r => r.isThreat && r.confidence >= this.config.minConfidenceThreshold,
        );

        let blocked = false;
        let blockReason = '';
        for (const r of activeThreats) {
            if (this._blockedCategories.has(r.category) || r.severity === Severity.CRITICAL) {
                blocked = true;
                blockReason = r.reason;
                break;
            }
        }

        let sanitizedText = text;
        if (this._sanitizer) {
            try {
                sanitizedText = this._sanitizer.sanitize(text);
            } catch {
                sanitizedText = text;
            }
        }
        for (const r of results) {
            if (r.sanitizedInput) {
                sanitizedText = r.sanitizedInput;
                break;
            }
        }

        return {
            inputText: text,
            results,
            blocked,
            blockReason,
            severity: PipelineResult.maxSeverity(activeThreats),
            sanitizedText,
        };
    }

    private _remember(key: string, result: PipelineResult): void {
        if (this._cache.size >= this.config.cacheSize) {
            const oldest = this._cache.keys().next().value;
            if (oldest !== undefined) this._cache.delete(oldest);
        }
        this._cache.set(key, result);
    }

    runSafe(text: string, context?: Record<string, unknown>): [boolean, PipelineResult] {
        const result = this.run(text, context);
        return [!result.blocked, result];
    }
}
