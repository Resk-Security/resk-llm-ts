# Getting started

## Install

```bash
npm install resk-llm-ts
```

## Minimal usage

```ts
import { ReskSecurity } from "resk-llm-ts";

const security = new ReskSecurity();
const safe = security.filterUserInput("Your prompt here");
console.log(safe.cleanedText);
```

See Configuration for production-ready settings.
