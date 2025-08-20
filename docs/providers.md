# Providers

Swap LLM providers by implementing `providers/llm_provider.ts` and wiring it up.

```ts
import { setProvider } from "resk-llm-ts";

setProvider({
  name: "openai",
  chat: async ({ messages, model }) => { /* ... */ }
});
```
