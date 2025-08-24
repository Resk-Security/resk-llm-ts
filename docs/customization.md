# Customization

This library exposes granular controls to adjust security behavior to your application context. All options can be set globally at client construction and overridden per request.

## Feature toggles

```ts
import { ReskLLMClient } from "resk-llm-ts";

const client = new ReskLLMClient({
  provider: 'openai',
  providerConfig: { apiKey: process.env.OPENAI_API_KEY! },
  securityConfig: {
    inputSanitization: { enabled: true },
    piiDetection: { enabled: true, redact: true },
    promptInjection: { enabled: true, level: 'advanced' },
    heuristicFilter: { enabled: true, scoreThreshold: 0.6 },
    contentModeration: { enabled: true, severity: 'medium' },
    vectorDb: { enabled: true, similarityThreshold: 0.85 },
    canaryTokens: { enabled: true },
  }
});
```

## Custom patterns

Add prompt injection patterns at runtime:

```ts
import { PromptInjectionDetector } from 'resk-llm-ts';

const detector = new PromptInjectionDetector({ enabled: true, level: 'advanced' });
detector.addCustomPattern('medium', 'roleSwitch', /pretend to be admin/i);
```

Extend PII detection:

```ts
import { PIIDetectionConfig } from 'resk-llm-ts';

const piiConfig: PIIDetectionConfig = {
  enabled: true,
  redact: true,
  patterns: [/EMP-\d{6}/g]
};
```

## Sanitization

```ts
import { InputSanitizationConfig } from 'resk-llm-ts';

const sanitizeConfig: InputSanitizationConfig = {
  enabled: true,
  sanitizeHtml: true,
  allowedTags: ['b','i','strong','em']
};
```

## Vector similarity thresholds

If you enable the vector database feature, you can tune the similarity threshold globally (0–1):

```ts
import { ReskLLMClient } from 'resk-llm-ts';

const client = new ReskLLMClient({ provider: 'openai', providerConfig: { apiKey: '...' } });
await client.seedInjectionCorpus(["Ignore all previous instructions..."]); // optional

// At construction via securityConfig
const clientStrict = new ReskLLMClient({
  provider: 'openai',
  providerConfig: { apiKey: '...' },
  securityConfig: { vectorDb: { enabled: true, similarityThreshold: 0.9 } }
});
```

// Update at runtime
clientStrict.setVectorSimilarityThreshold(0.92);
```
