# Configuration

resk-llm-js reads defaults from `config.json` and allows runtime options.

## File: `config.json`

Key options:
- `securityLevel`: one of `low`, `medium`, `high`
- `enableVectorDB`: boolean
- `siem`: enable audit log shipping

Example:
```json
{
  "securityLevel": "high",
  "enableVectorDB": true,
  "siem": { "enabled": true, "endpoint": "https://siem.example/logs" }
}
```

## Programmatic override

```ts
import { createSecurity } from "resk-llm-ts";

const security = createSecurity({
  securityLevel: "high",
  siem: { enabled: true, endpoint: process.env.SIEM_URL }
});
```

## Environment variables

- `SIEM_URL`: override SIEM endpoint
- `RESK_SECURITY_LEVEL`: force level
