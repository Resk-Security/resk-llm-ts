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

## Express middleware

```ts
import express from "express";
import { createExpressMiddleware } from "resk-llm-ts";

const app = express();
app.use(express.json());
app.use(createExpressMiddleware());
```
