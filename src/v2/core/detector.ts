// Severity levels
export enum Severity {
    INFO = 'info',
    LOW = 'low',
    MEDIUM = 'medium',
    HIGH = 'high',
    CRITICAL = 'critical',
}

// Threat categories matching the 10 vectors
export enum ThreatCategory {
    DIRECT_INJECTION = 'direct_injection',
    INDIRECT_INJECTION = 'indirect_injection',
    MULTIMODAL_INJECTION = 'multimodal_injection',
    DOCUMENT_INJECTION = 'document_injection',
    ENVIRONMENT_MANIPULATION = 'environment_manipulation',
    BYPASS_DETECTION = 'bypass_detection',
    MEMORY_POISONING = 'memory_poisoning',
    GOAL_HIJACK = 'goal_hijack',
    EXFILTRATION = 'exfiltration',
    INTER_AGENT_INJECTION = 'inter_agent_injection',
}

export interface DetectorMatch {
    name: string;
    match: string;
    category: string;
}

export interface DetectionResult {
    detector: string;
    isThreat: boolean;
    severity: Severity;
    category: ThreatCategory;
    confidence: number;
    reason: string;
    matches: DetectorMatch[];
    sanitizedInput: string | null;
}

export namespace DetectionResult {
    export function safe(detector: string, reason = 'No threat detected'): DetectionResult {
        return {
            detector,
            isThreat: false,
            severity: Severity.INFO,
            category: ThreatCategory.DIRECT_INJECTION,
            confidence: 0,
            reason,
            matches: [],
            sanitizedInput: null,
        };
    }

    export function threat(
        detector: string,
        category: ThreatCategory,
        options?: {
            severity?: Severity;
            confidence?: number;
            reason?: string;
            matches?: DetectorMatch[];
            sanitizedInput?: string | null;
        },
    ): DetectionResult {
        return {
            detector,
            isThreat: true,
            severity: options?.severity ?? Severity.MEDIUM,
            category,
            confidence: options?.confidence ?? 0.5,
            reason: options?.reason ?? `Threat detected by ${detector}`,
            matches: options?.matches ?? [],
            sanitizedInput: options?.sanitizedInput ?? null,
        };
    }
}

export interface BaseDetector {
    readonly name: string;
    readonly category: ThreatCategory;
    enabled: boolean;
    detect(text: string, context?: Record<string, unknown>): DetectionResult;
}
