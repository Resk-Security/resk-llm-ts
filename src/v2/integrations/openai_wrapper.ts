import { SecurityPipeline } from '../core/pipeline';
export class OpenAIWrapper {
    constructor(private _client: any, private _pipeline: SecurityPipeline = new SecurityPipeline()) {}
    async chat(messages: Array<{role: string; content: string}>) {
        const text = messages.map(m => m.content).join('\n');
        const r = this._pipeline.run(text);
        if (r.blocked) throw new Error(`Blocked: ${r.blockReason}`);
        return this._client.chat.completions.create({ messages });
    }
}
