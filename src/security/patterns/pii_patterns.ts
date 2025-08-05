/**
 * Basic regex patterns for common PII.
 * IMPORTANT: These are examples only and may not be comprehensive or perfectly accurate.
 * Real-world PII detection often requires more sophisticated methods (e.g., context analysis, NER models).
 * These should be reviewed and expanded based on specific requirements.
 */

// Re-exporting the default PII patterns from the main protector module for now
// Ideally, populate this file with more granular patterns as needed.

// Enhanced email patterns (includes obfuscation variants)
export const emailPattern: RegExp = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

// Obfuscated email patterns
export const obfuscatedEmailPatterns: RegExp[] = [
    // Standard email
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    // Bracket obfuscation: test[@]example[.]com
    /\b[A-Za-z0-9._%+-]+\[@\][A-Za-z0-9.-]+\[\.\][A-Za-z]{2,}\b/g,
    // Mixed bracket obfuscation
    /\b[A-Za-z0-9._%+-]+[?@]?[A-Za-z0-9.-]+[?.]?[A-Za-z0-9]{2,}\b/g,
    // Word substitution: test AT example DOT com
    /\b[A-Za-z0-9._%+-]+\s+(?:at|AT|At)\s+[A-Za-z0-9.-]+\s+(?:dot|DOT|Dot)\s+[A-Za-z]{2,}\b/g,
    // Character substitution (0 for o, etc.)
    /\b[A-Za-z0-9._%+-]+[@＠][A-Za-z0-9.-]*[0o][A-Za-z0-9.-]*\.[A-Za-z0-9]{2,}\b/g,
];

// Enhanced phone patterns (including obfuscated variants)
export const phonePatternNA: RegExp = /\b(?:\+?1[ -.]?)?[(]?\d{3}[)]?[ -.]?\d{3}[ -.]?\d{4}\b/g;

export const obfuscatedPhonePatterns: RegExp[] = [
    // Standard phone
    /\b(?:\+?1[ -.]?)?[(]?\d{3}[)]?[ -.]?\d{3}[ -.]?\d{4}\b/g,
    // With excessive spaces or symbols
    /\b(?:\+?1[\s.-]?)?[\(\[]?\d{3}[\)\]]?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
    // Dot/word separation: 555 DOT 123 DOT 4567
    /\b\d{3}[\s.]*(?:dot|DOT)[\s.]*\d{3}[\s.]*(?:dot|DOT)[\s.]*\d{4}\b/g,
];

// Enhanced credit card patterns
export const creditCardPattern: RegExp = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;

export const obfuscatedCreditCardPatterns: RegExp[] = [
    // Standard format
    /\b(?:\d{4}[ -]?){3}\d{4}\b/g,
    // With asterisks: 1234 **** **** 5678
    /\b\d{4}[\s*-]*\*{4}[\s*-]*\*{4}[\s*-]*\d{4}\b/g,
    // With X's: 1234 XXXX XXXX 5678
    /\b\d{4}[\sX-]*X{4}[\sX-]*X{4}[\sX-]*\d{4}\b/g,
    // Mixed obfuscation
    /\b\d{4}[\s*X-]{1,4}[\*X]{4}[\s*X-]{1,4}[\*X]{4}[\s*X-]{1,4}\d{4}\b/g,
];

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
    // Include obfuscated patterns for comprehensive detection
    ...obfuscatedEmailPatterns,
    ...obfuscatedPhonePatterns,
    ...obfuscatedCreditCardPatterns,
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