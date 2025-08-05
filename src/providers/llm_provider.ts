/**
 * Abstraction pour les fournisseurs de LLM
 * Permet d'utiliser le même système de sécurité avec différents providers
 */

export interface LLMMessage {
    role: 'system' | 'user' | 'assistant';
    content: string;
    name?: string;
    function_call?: unknown;
    tool_calls?: unknown;
}

export interface LLMCompletionRequest {
    model: string;
    messages: LLMMessage[];
    max_tokens?: number;
    temperature?: number;
    top_p?: number;
    frequency_penalty?: number;
    presence_penalty?: number;
    stop?: string | string[];
    stream?: boolean;
    functions?: unknown[];
    tools?: unknown[];
    [key: string]: unknown; // Pour les paramètres spécifiques au provider
}

export interface LLMCompletionResponse {
    id: string;
    object: string;
    created: number;
    model: string;
    choices: {
        index: number;
        message: LLMMessage;
        finish_reason: string | null;
    }[];
    usage?: {
        prompt_tokens: number;
        completion_tokens: number;
        total_tokens: number;
    };
    [key: string]: unknown; // Pour les champs spécifiques au provider
}

export interface LLMProviderConfig {
    apiKey: string;
    baseUrl?: string;
    timeout?: number;
    headers?: Record<string, string>;
    maxRetries?: number;
    retryDelay?: number;
}

export interface EmbeddingResponse {
    data: Array<{
        object: string;
        embedding: number[];
        index: number;
    }>;
    model: string;
    usage: {
        prompt_tokens: number;
        total_tokens: number;
    };
}

/**
 * Interface abstraite pour tous les fournisseurs LLM
 */
export abstract class LLMProvider {
    protected config: LLMProviderConfig;
    protected providerName: string;

    constructor(config: LLMProviderConfig, providerName: string) {
        this.config = config;
        this.providerName = providerName;
    }

    /**
     * Génère une completion de chat
     */
    abstract chatCompletion(request: LLMCompletionRequest): Promise<LLMCompletionResponse>;

    /**
     * Génère des embeddings (optionnel)
     */
    async generateEmbedding(text: string, model?: string): Promise<number[]> {
        throw new Error(`${this.providerName} does not support embeddings. Use OpenAI for embeddings.`);
    }

    /**
     * Retourne la liste des modèles disponibles
     */
    abstract getAvailableModels(): Promise<string[]>;

    /**
     * Valide la configuration
     */
    abstract validateConfig(): Promise<boolean>;

    /**
     * Normalise une requête vers le format du provider
     */
    protected abstract normalizeRequest(request: LLMCompletionRequest): unknown;

    /**
     * Normalise une réponse vers le format standard
     */
    protected abstract normalizeResponse(response: unknown): LLMCompletionResponse;

    /**
     * Obtient le nom du provider
     */
    getProviderName(): string {
        return this.providerName;
    }

    /**
     * Teste la connectivité
     */
    async testConnection(): Promise<boolean> {
        try {
            const testRequest: LLMCompletionRequest = {
                model: await this.getDefaultModel(),
                messages: [{ role: 'user', content: 'Hello' }],
                max_tokens: 5
            };
            
            await this.chatCompletion(testRequest);
            return true;
        } catch (error) {
            console.error(`[${this.providerName}] Connection test failed:`, error);
            return false;
        }
    }

    /**
     * Obtient le modèle par défaut pour ce provider
     */
    protected abstract getDefaultModel(): Promise<string>;
}

/**
 * Provider pour OpenAI/OpenRouter (existant)
 */
export class OpenAIProvider extends LLMProvider {
    private client: any; // Type OpenAI client

    constructor(config: LLMProviderConfig, openaiClient?: any) {
        super(config, 'openai');
        
        if (openaiClient) {
            this.client = openaiClient;
        } else {
            // Dynamic import OpenAI to avoid hard dependency
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            const OpenAI = require('openai');
            this.client = new OpenAI({
                apiKey: config.apiKey,
                baseURL: config.baseUrl || 'https://api.openai.com/v1',
                timeout: config.timeout || 30000,
                defaultHeaders: config.headers
            });
        }
    }

    async chatCompletion(request: LLMCompletionRequest): Promise<LLMCompletionResponse> {
        const normalizedRequest = this.normalizeRequest(request);
        const response = await this.client.chat.completions.create(normalizedRequest);
        return this.normalizeResponse(response);
    }

    async generateEmbedding(text: string, model: string = 'text-embedding-3-small'): Promise<number[]> {
        const response = await this.client.embeddings.create({
            input: text,
            model: model
        });
        return response.data[0].embedding;
    }

    async getAvailableModels(): Promise<string[]> {
        try {
            const response = await this.client.models.list();
            return response.data.map((model: any) => model.id);
        } catch (error) {
            console.warn('[OpenAI] Could not fetch models list:', error);
            return ['gpt-4', 'gpt-3.5-turbo', 'gpt-4-turbo'];
        }
    }

    async validateConfig(): Promise<boolean> {
        try {
            await this.client.models.list();
            return true;
        } catch (error) {
            return false;
        }
    }

    protected normalizeRequest(request: LLMCompletionRequest): any {
        // OpenAI format is already our standard
        return {
            ...request,
            messages: request.messages.map(msg => ({
                role: msg.role,
                content: msg.content,
                ...(msg.name && { name: msg.name }),
                ...((msg as any).function_call && { function_call: (msg as any).function_call }),
                ...((msg as any).tool_calls && { tool_calls: (msg as any).tool_calls })
            }))
        };
    }

    protected normalizeResponse(response: any): LLMCompletionResponse {
        // OpenAI format is already our standard
        return response;
    }

    protected async getDefaultModel(): Promise<string> {
        return 'gpt-3.5-turbo';
    }
}

/**
 * Provider pour Anthropic Claude
 */
export class AnthropicProvider extends LLMProvider {
    constructor(config: LLMProviderConfig) {
        super(config, 'anthropic');
    }

    async chatCompletion(request: LLMCompletionRequest): Promise<LLMCompletionResponse> {
        const normalizedRequest = this.normalizeRequest(request);
        
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.config.apiKey,
                'anthropic-version': '2023-06-01',
                ...this.config.headers
            },
            body: JSON.stringify(normalizedRequest)
        });

        if (!response.ok) {
            throw new Error(`Anthropic API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        return this.normalizeResponse(data);
    }

    async getAvailableModels(): Promise<string[]> {
        return [
            'claude-3-opus-20240229',
            'claude-3-sonnet-20240229', 
            'claude-3-haiku-20240307',
            'claude-2.1',
            'claude-2.0'
        ];
    }

    async validateConfig(): Promise<boolean> {
        try {
            await this.testConnection();
            return true;
        } catch (error) {
            return false;
        }
    }

    protected normalizeRequest(request: LLMCompletionRequest): any {
        // Convertir au format Anthropic
        const systemMessage = request.messages.find(m => m.role === 'system');
        const userMessages = request.messages.filter(m => m.role !== 'system');

        return {
            model: request.model,
            max_tokens: request.max_tokens || 1000,
            temperature: request.temperature,
            top_p: request.top_p,
            stop_sequences: Array.isArray(request.stop) ? request.stop : request.stop ? [request.stop] : undefined,
            system: systemMessage?.content,
            messages: userMessages.map(msg => ({
                role: msg.role === 'assistant' ? 'assistant' : 'user',
                content: msg.content
            }))
        };
    }

    protected normalizeResponse(response: any): LLMCompletionResponse {
        // Convertir depuis le format Anthropic vers notre format standard
        return {
            id: response.id,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: response.model,
            choices: [{
                index: 0,
                message: {
                    role: 'assistant',
                    content: response.content?.[0]?.text || ''
                },
                finish_reason: response.stop_reason
            }],
            usage: {
                prompt_tokens: response.usage?.input_tokens || 0,
                completion_tokens: response.usage?.output_tokens || 0,
                total_tokens: (response.usage?.input_tokens || 0) + (response.usage?.output_tokens || 0)
            }
        };
    }

    protected async getDefaultModel(): Promise<string> {
        return 'claude-3-sonnet-20240229';
    }
}

/**
 * Provider pour Cohere
 */
export class CohereProvider extends LLMProvider {
    constructor(config: LLMProviderConfig) {
        super(config, 'cohere');
    }

    async chatCompletion(request: LLMCompletionRequest): Promise<LLMCompletionResponse> {
        const normalizedRequest = this.normalizeRequest(request);
        
        const response = await fetch('https://api.cohere.ai/v1/chat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.config.apiKey}`,
                ...this.config.headers
            },
            body: JSON.stringify(normalizedRequest)
        });

        if (!response.ok) {
            throw new Error(`Cohere API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        return this.normalizeResponse(data);
    }

    async generateEmbedding(text: string, model: string = 'embed-english-v3.0'): Promise<number[]> {
        const response = await fetch('https://api.cohere.ai/v1/embed', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.config.apiKey}`
            },
            body: JSON.stringify({
                texts: [text],
                model: model,
                input_type: 'search_document'
            })
        });

        if (!response.ok) {
            throw new Error(`Cohere Embed API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        return data.embeddings[0];
    }

    async getAvailableModels(): Promise<string[]> {
        return [
            'command-r-plus',
            'command-r', 
            'command',
            'command-light',
            'command-nightly'
        ];
    }

    async validateConfig(): Promise<boolean> {
        try {
            await this.testConnection();
            return true;
        } catch (error) {
            return false;
        }
    }

    protected normalizeRequest(request: LLMCompletionRequest): any {
        // Convertir au format Cohere
        const systemMessage = request.messages.find(m => m.role === 'system');
        const chatHistory = request.messages.filter(m => m.role !== 'system' && m.role !== 'user');
        const userMessage = request.messages.filter(m => m.role === 'user').pop();

        return {
            model: request.model,
            message: userMessage?.content || '',
            chat_history: chatHistory.map(msg => ({
                role: msg.role.toUpperCase(),
                message: msg.content
            })),
            preamble: systemMessage?.content,
            max_tokens: request.max_tokens,
            temperature: request.temperature,
            p: request.top_p,
            stop_sequences: Array.isArray(request.stop) ? request.stop : request.stop ? [request.stop] : undefined
        };
    }

    protected normalizeResponse(response: any): LLMCompletionResponse {
        // Convertir depuis le format Cohere vers notre format standard
        return {
            id: response.generation_id || `cohere-${Date.now()}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: 'command', // Cohere ne retourne pas toujours le modèle
            choices: [{
                index: 0,
                message: {
                    role: 'assistant',
                    content: response.text || ''
                },
                finish_reason: response.finish_reason || null
            }],
            usage: {
                prompt_tokens: response.meta?.billed_units?.input_tokens || 0,
                completion_tokens: response.meta?.billed_units?.output_tokens || 0,
                total_tokens: (response.meta?.billed_units?.input_tokens || 0) + (response.meta?.billed_units?.output_tokens || 0)
            }
        };
    }

    protected async getDefaultModel(): Promise<string> {
        return 'command-r';
    }
}

/**
 * Provider pour HuggingFace
 */
export class HuggingFaceProvider extends LLMProvider {
    constructor(config: LLMProviderConfig) {
        super({
            ...config,
            baseUrl: config.baseUrl || 'https://api-inference.huggingface.co'
        }, 'huggingface');
    }

    async chatCompletion(request: LLMCompletionRequest): Promise<LLMCompletionResponse> {
        const normalizedRequest = this.normalizeRequest(request);
        
        const response = await fetch(`${this.config.baseUrl}/models/${request.model}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.config.apiKey}`,
                ...this.config.headers
            },
            body: JSON.stringify(normalizedRequest)
        });

        if (!response.ok) {
            throw new Error(`HuggingFace API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        return this.normalizeResponse(data);
    }

    async generateEmbedding(text: string, model: string = 'sentence-transformers/all-MiniLM-L6-v2'): Promise<number[]> {
        const response = await fetch(`${this.config.baseUrl}/models/${model}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.config.apiKey}`
            },
            body: JSON.stringify({
                inputs: text
            })
        });

        if (!response.ok) {
            throw new Error(`HuggingFace Embedding API error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        return Array.isArray(data) ? data : data.embeddings || [];
    }

    async getAvailableModels(): Promise<string[]> {
        return [
            'microsoft/DialoGPT-large',
            'microsoft/DialoGPT-medium',
            'facebook/blenderbot-400M-distill',
            'microsoft/phi-2',
            'meta-llama/Llama-2-7b-chat-hf'
        ];
    }

    async validateConfig(): Promise<boolean> {
        try {
            await this.testConnection();
            return true;
        } catch (error) {
            return false;
        }
    }

    protected normalizeRequest(request: LLMCompletionRequest): any {
        // Convertir au format HuggingFace
        const conversationText = request.messages
            .map(msg => `${msg.role}: ${msg.content}`)
            .join('\n') + '\nassistant:';

        return {
            inputs: conversationText,
            parameters: {
                max_new_tokens: request.max_tokens || 100,
                temperature: request.temperature || 0.7,
                top_p: request.top_p,
                stop: request.stop,
                return_full_text: false
            }
        };
    }

    protected normalizeResponse(response: any): LLMCompletionResponse {
        // Convertir depuis le format HuggingFace vers notre format standard
        const generated_text = Array.isArray(response) ? response[0]?.generated_text : response.generated_text;
        
        return {
            id: `hf-${Date.now()}`,
            object: 'chat.completion',
            created: Math.floor(Date.now() / 1000),
            model: 'huggingface-model',
            choices: [{
                index: 0,
                message: {
                    role: 'assistant',
                    content: generated_text || ''
                },
                finish_reason: 'stop'
            }],
            usage: {
                prompt_tokens: 0, // HF n'expose pas ces métriques facilement
                completion_tokens: 0,
                total_tokens: 0
            }
        };
    }

    protected async getDefaultModel(): Promise<string> {
        return 'microsoft/DialoGPT-medium';
    }
}

/**
 * Factory pour créer des providers
 */
export class ProviderFactory {
    static createProvider(
        providerType: 'openai' | 'anthropic' | 'cohere' | 'huggingface',
        config: LLMProviderConfig,
        openaiClient?: any
    ): LLMProvider {
        switch (providerType) {
            case 'openai':
                return new OpenAIProvider(config, openaiClient);
            case 'anthropic':
                return new AnthropicProvider(config);
            case 'cohere':
                return new CohereProvider(config);
            case 'huggingface':
                return new HuggingFaceProvider(config);
            default:
                throw new Error(`Unsupported provider type: ${providerType}`);
        }
    }

    static getSupportedProviders(): string[] {
        return ['openai', 'anthropic', 'cohere', 'huggingface'];
    }
}