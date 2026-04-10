export class RESKError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'RESKError';
    }
}

export class DetectionError extends RESKError {
    constructor(
        public readonly detector: string,
        message: string,
        public readonly original?: Error,
    ) {
        super(`[${detector}] ${message}`);
        this.name = 'DetectionError';
    }
}

export class PipelineError extends RESKError {
    constructor(
        message: string,
        public readonly results: Array<{ detector: string; isThreat: boolean }>,
    ) {
        super(message);
        this.name = 'PipelineError';
    }
}

export class ConfigurationError extends RESKError {
    constructor(message: string) {
        super(message);
        this.name = 'ConfigurationError';
    }
}
