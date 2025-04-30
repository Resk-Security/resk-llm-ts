/**
 * Example patterns for content that might be prohibited based on policy.
 * These are highly dependent on the specific use case and MUST be customized.
 */
export const defaultProhibitedEngPatterns: RegExp[] = [
    // Examples: Specific product names, internal codenames, certain competitive terms
    /\bProject[ -]?Confidential\b/i,
    /\bCompetitorX\b/i,
    
    // Example: Discouraging discussion of illegal acts (very basic)
    /how\s+to\s+(?:build|make|create)\s+a\s+bomb/i,
    /instructions\s+for\s+illegal\s+activity/i,
];

// Placeholder for prohibited patterns (English)
// e.g., export const prohibitedEngRegex: RegExp[] = [/bad_word/i, /another_pattern/i];
export {}; 