# Vector DB integration

This library includes utilities to store and query vectorized content.

See `examples/vector_db_setup.ts` for a runnable setup.

## Basic flow

1. Normalize text
2. Generate embeddings with your provider
3. Upsert into your vector store
4. Query with nearest neighbors

```ts
import { createVectorStore } from "resk-llm-ts";

const store = createVectorStore();
await store.upsert("doc-1", [0.1, 0.2, 0.3], { title: "Doc" });
const results = await store.query([0.09, 0.22, 0.31], 5);
```
