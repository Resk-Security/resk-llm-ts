/**
 * Example list of prohibited words.
 * This list should be carefully curated based on content policy.
 * Consider using this for exact word matching, often case-insensitive.
 */
export const defaultProhibitedWords: string[] = [
    // Example offensive terms (replace with actual policy-violating words)
    'exampleoffensiveword1',
    'exampleoffensiveword2',
    
    // Example competitor names (if policy prohibits mentioning them)
    'competitor_a',
    'competitor_b',
    
    // Example internal code names
    'project_alpha',
];

// Often used with a regex like:
// const regex = new RegExp(`\\b(?:${defaultProhibitedWords.join('|')})\\b`, 'i');

// Placeholder for prohibited words list
// e.g., export const prohibitedWords: string[] = ['word1', 'word2'];
export {}; 