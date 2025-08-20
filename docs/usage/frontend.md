# Frontend usage

Use the `frontend/resk_security_filter` helpers to sanitize UI inputs.

```ts
import { createFrontendSecurityFilter } from "resk-llm-ts/frontend";

const filter = createFrontendSecurityFilter();
const output = filter.clean("user prompt");
console.log(output.cleanedText);
```

Combine with `security_cache` and `performance_optimizer` for UX.

