import { DetectionResult, type BaseDetector, Severity, ThreatCategory, type DetectorMatch } from './detector';
import { DEFAULT_CONFIG, type SecurityConfig } from './config';

export interface PipelineResult {
    inputText: string;
    results: DetectionResult[];
    blocked: boolean;
    blockReason: string;
    severity: Severity;
    sanitizedText: string;
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
    private config = DEFAULT_CONFIG;
    private _blockedCategories: Set<string>;

    constructor(config?: SecurityConfig) {
        if (config) {
            this.config = { ...DEFAULT_CONFIG, ...config };
        }
        this._blockedCategories = new Set(this.config.blockCategories);
    }

    get detectors(): ReadonlyArray<BaseDetector> {
        return this._detectors;
    }

    add(detector: BaseDetector): this {
        this._detectors.push(detector);
        return this;
    }

    remove(name: string): boolean {
        const before = this._detectors.length;
        this._detectors = this._detectors.filter(d => d.name !== name);
        return this._detectors.length < before;
    }

    run(text: string, context?: Record<string, unknown>): PipelineResult {
        const results: DetectionResult[] = [];

        for (const detector of this._detectors) {
            if (!detector.enabled) continue;
            try {
                const r = detector.detect(text, context);
                results.push(r);
            } catch (e) {
                results.push(DetectionResult.safe(
                    detector.name,
                    `Detector error: ${e instanceof Error ? e.message : String(e)}`,
                ));
            }
        }

        let blocked = false;
        let blockReason = '';
        for (const r of results) {
            if (r.isThreat && (
                this._blockedCategories.has(r.category) ||
                r.severity === Severity.CRITICAL
            )) {
                blocked = true;
                blockReason = r.reason;
                break;
            }
        }

        let sanitizedText = text;
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
            severity: PipelineResult.maxSeverity(results),
            sanitizedText,
        };
    }

    runSafe(text: string, context?: Record<string, unknown>): [boolean, PipelineResult] {
        const result = this.run(text, context);
        return [!result.blocked, result];
    }
}
