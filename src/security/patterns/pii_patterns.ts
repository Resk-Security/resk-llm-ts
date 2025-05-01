/**
 * Basic regex patterns for common PII.
 * IMPORTANT: These are examples only and may not be comprehensive or perfectly accurate.
 * Real-world PII detection often requires more sophisticated methods (e.g., context analysis, NER models).
 * These should be reviewed and expanded based on specific requirements.
 */

// Re-exporting the default PII patterns from the main protector module for now
// Ideally, populate this file with more granular patterns as needed.

// Make sure this matches test@example.com used in tests
export const emailPattern: RegExp = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

// Basic North American phone number patterns
export const phonePatternNA: RegExp = /\b(?:\+?1[ -.]?)?[(]?\d{3}[)]?[ -.]?\d{3}[ -.]?\d{4}\b/g;

// Basic Credit Card number patterns (does not perform Luhn check)
export const creditCardPattern: RegExp = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;

// Basic IPv4 Address pattern
export const ipAddressV4Pattern: RegExp = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

// Basic US Social Security Number pattern (SSN) - Use with extreme caution, prone to false positives
// export const ssnPatternUS: RegExp = /\b\d{3}[ -]?\d{2}[ -]?\d{4}\b/g;

// --- Default Exported List --- 

export const defaultPiiPatterns: RegExp[] = [
    emailPattern,
    phonePatternNA,
    creditCardPattern,
    ipAddressV4Pattern,
    // Add other patterns here, e.g.:
    // ssnPatternUS, 
];

// Example structure if defining directly here:
/*
export const emailPattern: RegExp = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
export const phonePatternNA: RegExp = /\b(?:\+?1[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}\b/g;
export const creditCardPattern: RegExp = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;
export const ipAddressV4Pattern: RegExp = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

export const defaultPiiPatterns: RegExp[] = [
    emailPattern,
    phonePatternNA,
    creditCardPattern,
    ipAddressV4Pattern,
];
*/ 