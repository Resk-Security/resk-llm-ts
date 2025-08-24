# Patterns & rules

Built-in categories:
- Prompt injection patterns
- PII leakage patterns
- Toxic content patterns
- Malicious URL patterns

Files live in `src/security/patterns/`.

## Add a new pattern

```ts
import { PromptInjectionDetector } from "resk-llm-ts";

const detector = new PromptInjectionDetector({ enabled: true, level: 'advanced' });
detector.addCustomPattern('high', 'leakage', /\b(?:\d{1,3}\.){3}\d{1,3}\b/);
```

## Vector similarity corpus

Combine regex patterns with semantic similarity. A minimal corpus is exported from `src/security/patterns/llm_injection_patterns.ts` as `canonicalInjectionCorpus`.

```ts
import { ReskLLMClient } from 'resk-llm-ts';
import { canonicalInjectionCorpus } from '../src/security/patterns/llm_injection_patterns';

const client = new ReskLLMClient({ provider: 'openai', providerConfig: { apiKey: '...' } });
await client.seedInjectionCorpus(canonicalInjectionCorpus, { source: 'builtin' });
```
