# Providers

The client supports multiple backend providers through a common abstraction defined in `src/providers/llm_provider.ts`.

## Selecting a provider

```ts
import { ReskLLMClient } from 'resk-llm-ts';

const client = new ReskLLMClient({
  provider: 'openai',
  providerConfig: { apiKey: process.env.OPENAI_API_KEY }
});

// Alternative: provider injection (for testing or custom providers)
// const client = new ReskLLMClient({ llmProvider: myCustomProvider });
```

Supported identifiers: `openai`, `anthropic`, `cohere`, `huggingface`.

## Embeddings

If the selected provider implements `generateEmbedding`, vector similarity features will be enabled automatically (when `vectorDb.enabled` is true). Otherwise, pass a custom embedding function.

```ts
const client = new ReskLLMClient({
  provider: 'openai',
  providerConfig: { apiKey: process.env.OPENAI_API_KEY },
  // or
  // embeddingFunction: async (text) => myEmbed(text)
});
```

## Custom providers

Implement the `LLMProvider` interface and pass it via `llmProvider`.
