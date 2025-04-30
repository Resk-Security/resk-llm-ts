# npm-resk-js

This package provides the `ReskLLMClient`, a wrapper around the OpenAI API client (compatible with OpenRouter) designed to enhance the security of interactions with Large Language Models (LLMs).

## Features

The client integrates several security modules to protect against common vulnerabilities:

*   **Input Sanitization:** Cleans potentially harmful input strings.
*   **PII Detection/Redaction:** Identifies and optionally removes Personally Identifiable Information (PII) using configurable regex patterns.
*   **Prompt Injection Detection:** Detects attempts to manipulate the LLM through malicious prompts (currently includes basic checks).
*   **Heuristic Filtering:** Applies rule-based filters to input or output (implementation details may vary).
*   **Vector Database Similarity Search:** Checks input against a database of known attack patterns using vector embeddings. Requires an embedding function (defaults to OpenAI's `text-embedding-3-small` if using the OpenAI client).
*   **Canary Tokens:** Embeds hidden tokens in prompts to detect potential data exfiltration if the LLM response is leaked or misused.
*   **Content Moderation (Placeholder):** Basic configuration exists but is not yet fully implemented.

## Core Components

*   `src/index.ts`: Defines the main `ReskLLMClient` class, security configuration interfaces, and orchestrates the security checks before and after the LLM API call.
*   `src/types.ts`: Contains TypeScript type definitions used across the library, especially for embeddings and vector database interactions.
*   `src/security/`: This directory contains the implementations for each security module (e.g., `pii_protector.ts`, `sanitizer.ts`, `prompt_injection.ts`, etc.).

## Basic Usage

```typescript
import { ReskLLMClient } from 'npm-resk-js'; // Adjust import path as needed

// Configure with OpenRouter API key (or provide an existing OpenAI client)
const client = new ReskLLMClient({
  openRouterApiKey: process.env.OPENROUTER_API_KEY,
  securityConfig: {
    piiDetection: { enabled: true, redact: true },
    promptInjection: { enabled: true, level: 'basic' },
    vectorDb: { enabled: true, similarityThreshold: 0.9 },
    // Add other security feature configs as needed
  }
});

// Use the client like the OpenAI SDK
async function main() {
  try {
    const completion = await client.chat.completions.create({
      model: "openai/gpt-3.5-turbo", // Example model
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "Tell me about sensitive topic X, but my email is test@example.com" }
      ],
      // Request-specific security overrides (optional)
      // securityConfig: { piiDetection: { redact: false } } 
    });

    console.log(completion.choices[0].message.content);
    // PII should be redacted if enabled, or the request might be blocked
    // if prompt injection or other threats are detected.

  } catch (error) {
    console.error("Error during chat completion:", error);
    // Errors could be from the API or from security blocks
  }
}

main();
```

