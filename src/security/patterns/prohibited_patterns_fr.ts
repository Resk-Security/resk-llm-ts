/**
 * Example patterns for content that might be prohibited based on policy (French).
 * These are highly dependent on the specific use case and MUST be customized.
 */
export const defaultProhibitedFrPatterns: RegExp[] = [
    // Examples: Specific product names, internal codenames, certain competitive terms (French equivalents)
    /\bProjet[ -]?Confidentiel\b/i,
    /\bConcurrentX\b/i,

    // Example: Discouraging discussion of illegal acts (French equivalents - very basic)
    /comment\s+fabriquer\s+une\s+bombe/i,
    /instructions\s+pour\s+activit(é|e)s?\s+ill(é|e)gales?/i, 
];

// Placeholder for prohibited patterns (French)
// e.g., export const prohibitedFrRegex: RegExp[] = [/mauvais_mot/i, /autre_motif/i];
export {}; 