/**
 * Basic patterns commonly associated with prompt injection attempts.
 * These should be expanded significantly based on known attack vectors.
 */
export const defaultInjectionPatterns: RegExp[] = [
    // Instruction overriding
    /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/i,
    /disregard\s+(?:your\s+)?(?:guidelines|rules|previous|prior|above)/i,
    /forget\s+what\s+i\s+(?:told|said)\s+you/i,
    /you\s+are\s+(?:now|henceforth)\s+in\s+.*\s+mode/i,
    /act\s+as\s+[\w\s]+(?:,|\s+with)?\s+no\s+restrictions/i,
    /you\s+will\s+(?:now|henceforth)\s+do\s+exactly\s+as\s+i\s+say/i,
    /developer\s+mode\s+enabled/i,
    /pretend\s+to\s+be/i,
    
    // System prompt leakage
    /reveal\s+(?:your|the)\s+(?:system\s+)?prompt/i,
    /print\s+(?:your|the)\s+initial\s+(?:instructions|prompt)/i,
    /what\s+are\s+your\s+instructions/i,
    /repeat\s+the\s+text\s+above/i, // Can be used maliciously

    // Obfuscation attempts
    /d\s*i\s*s\s*r\s*e\s*g\s*a\s*r\s*d/i, 
    /i\s*g\s*n\s*o\s*r\s*e/i, 
];

// Placeholder for LLM injection patterns (e.g., export const injectionPatterns: RegExp[] = [/.../];)
export {}; 