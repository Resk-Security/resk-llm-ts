# Customization

You can enable/disable filters, extend patterns, and adjust sanitization.

## Filters

```ts
import { SecurityFilters } from "resk-llm-ts";

const filters: SecurityFilters = {
  promptInjection: { enabled: true },
  pii: { enabled: true },
  toxicContent: { enabled: true },
};
```

## Extend patterns

```ts
import { addCustomPattern } from "resk-llm-ts";

addCustomPattern({
  id: "block-support-contact",
  description: "Prevent asking for support email",
  regex: /support@company\.com/i,
  severity: "medium"
});
```

## Sanitizer options

```ts
import { createSanitizer } from "resk-llm-ts";

const sanitizer = createSanitizer({
  allowHtml: false,
  stripInvisibleText: true,
});
```
