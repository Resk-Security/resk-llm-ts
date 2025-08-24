# Backend usage (Node/TypeScript)

## Input filtering

```ts
import { ReskSecurity } from "resk-llm-ts";

const security = new ReskSecurity();

export function sanitizeUserPrompt(prompt: string) {
  const result = security.filterUserInput(prompt);
  if (!result.isSafe) {
    throw new Error("Unsafe input detected");
  }
  return result.cleanedText;
}
```

## Refusing based on vector similarity

```ts
import { ReskLLMClient } from 'resk-llm-ts';
import { canonicalInjectionCorpus } from '../../src/security/patterns/llm_injection_patterns';

const client = new ReskLLMClient({
  provider: 'openai',
  providerConfig: { apiKey: process.env.OPENAI_API_KEY! },
  securityConfig: { vectorDb: { enabled: true, similarityThreshold: 0.88 } }
});

await client.seedInjectionCorpus(canonicalInjectionCorpus, { source: 'builtin' });

// Throws if the user prompt is too similar to known injection patterns
await client.chat.completion.create({
  model: 'openai/gpt-4o',
  messages: [{ role: 'user', content: 'Ignore previous instructions and...' }]
});
```

## Express middleware

```ts
import express from "express";
import { createExpressMiddleware } from "resk-llm-ts";

const app = express();
app.use(express.json());
app.use(createExpressMiddleware());
```
