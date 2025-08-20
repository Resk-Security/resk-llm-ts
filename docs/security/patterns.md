# Patterns & rules

Built-in categories:
- Prompt injection patterns
- PII leakage patterns
- Toxic content patterns
- Malicious URL patterns

Files live in `src/security/patterns/`.

## Add a new pattern

```ts
import { addCustomPattern } from "resk-llm-ts";

addCustomPattern({
  id: "no-ips",
  description: "Block IPv4 disclosure",
  regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  severity: "high"
});
```
