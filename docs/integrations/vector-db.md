# Vector DB integration

The client includes an in-memory vector database to prototype semantic similarity detection. For production, replace it with a managed service by implementing the `IVectorDatabase` interface.

## Use cases

- Store canonical prompt injections and detect semantically similar user inputs
- Maintain organization-specific blocklists that go beyond regex

## Enabling similarity detection

```ts
import { ReskLLMClient } from 'resk-llm-ts';
import { canonicalInjectionCorpus } from '../../src/security/patterns/llm_injection_patterns';

const client = new ReskLLMClient({
  provider: 'openai',
  providerConfig: { apiKey: process.env.OPENAI_API_KEY },
  securityConfig: { vectorDb: { enabled: true, similarityThreshold: 0.85 } }
});

// Seed a corpus of known attacks
await client.seedInjectionCorpus(canonicalInjectionCorpus, { category: 'injection' });
```

## How blocking works

During pre-checks, the user message is embedded and compared to the stored corpus using cosine similarity. If the maximum similarity exceeds `similarityThreshold`, the request is blocked before calling the provider.

## Custom vector DB

Implement `IVectorDatabase` and pass it as `vectorDbInstance` to the client if you want to use Pinecone/Weaviate/Chroma:

```ts
import { IVectorDatabase, SimilarityResult, VectorMetadata } from 'resk-llm-ts';

class MyVectorDb implements IVectorDatabase {
  isEnabled() { return true; }
  async addTextEntry(text: string, metadata?: VectorMetadata) { /* ... */ return 'id'; }
  addEntry(vector: number[], metadata?: VectorMetadata) { /* ... */ return 'id'; }
  async searchSimilarText(text: string, k?: number, threshold?: number): Promise<SimilarityResult> { /* ... */ return { detected: false, max_similarity: 0, similar_entries: [] }; }
  searchSimilarVector(queryVector: number[], k?: number, threshold?: number): SimilarityResult { /* ... */ return { detected: false, max_similarity: 0, similar_entries: [] }; }
  async detect(text: string): Promise<SimilarityResult> { /* ... */ return { detected: false, max_similarity: 0, similar_entries: [] }; }
}

const client = new ReskLLMClient({
  provider: 'openai',
  providerConfig: { apiKey: '...' },
  vectorDbInstance: new MyVectorDb()
});
```

## Tuning thresholds

Lower thresholds increase recall (more blocks) and may raise false positives. Start at 0.85–0.9 for conservative behavior.
