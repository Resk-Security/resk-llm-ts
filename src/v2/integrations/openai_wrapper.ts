import { SecurityPipeline } from '../core/pipeline.js';
import { OutputValidator, type ValidationResult } from '../protection/output_validator.js';
import { createDefaultPipeline } from '../defaults.js';

interface ChatCompletionClient {
    chat: {
        completions: {
            create(input: { messages: Array<{ role: string; content: string }> }): Promise<unknown>;
        };
    };
}

export interface OpenAIWrapperOptions {
    pipeline?: SecurityPipeline;
    validator?: OutputValidator;
    /** Throw when the model output fails validation (default `true`). */
    blockUnsafeOutput?: boolean;
}

type OptionsArg = OpenAIWrapperOptions | SecurityPipeline;

function isPipeline(value: OptionsArg): value is SecurityPipeline {
    return value instanceof SecurityPipeline;
}

/** Best-effort extraction of the text content from an OpenAI-style response. */
export function extractOutputText(response: unknown): string {
    if (!response || typeof response !== 'object') return '';
    const r = response as Record<string, unknown>;
    if (typeof r.output_text === 'string') return r.output_text;
    const choices = r.choices;
    if (Array.isArray(choices) && choices.length > 0) {
        const message = (choices[0] as Record<string, unknown>)?.message as Record<string, unknown> | undefined;
        if (message && typeof message.content === 'string') return message.content;
    }
    return '';
}

export class OpenAIWrapper {
    private _pipeline: SecurityPipeline;
    private _validator: OutputValidator;
    private _blockUnsafeOutput: boolean;

    constructor(private _client: ChatCompletionClient, options: OptionsArg = {}) {
        const opts: OpenAIWrapperOptions = isPipeline(options) ? { pipeline: options } : options;
        this._pipeline = opts.pipeline ?? createDefaultPipeline();
        this._validator = opts.validator ?? new OutputValidator();
        this._blockUnsafeOutput = opts.blockUnsafeOutput ?? true;
    }

    /** Scan the input, call the model, then validate the output. */
    async chat(messages: Array<{ role: string; content: string }>, context?: Record<string, unknown>) {
        const text = messages.map(m => m.content).join('\n');
        const scan = this._pipeline.run(text, context);
        if (scan.blocked) throw new Error(`Blocked: ${scan.blockReason}`);

        const response = await this._client.chat.completions.create({ messages });

        const validation: ValidationResult = this._validator.validate(extractOutputText(response));
        if (!validation.isSafe && this._blockUnsafeOutput) {
            throw new Error(`Unsafe model output: ${validation.issues.map(i => i.type).join(', ')}`);
        }
        return response;
    }
}
