/**
 * Patterns to detect common special tokens used by LLMs.
 * These might need adjustment based on the specific models being used.
 */
export const defaultSpecialTokenPatterns: RegExp[] = [
    // Common examples
    /<\|endoftext\|>/g,          // GPT
    /<\|im_start\|>/g,          // ChatML
    /<\|im_end\|>/g,            // ChatML
    /<s>/g,                     // Llama, Mistral
    /<\/s>/g,                    // Llama, Mistral
    /\[INST\]/g,               // Llama, Mistral instruction
    /<\/\[INST\]/g,              // Llama, Mistral instruction end
    /\[BOS\]/g,                 // Beginning of Sequence
    /\[EOS\]/g,                 // End of Sequence
];

// Could also be used to sanitize/remove these tokens from user input or LLM output if necessary.

// Placeholder for special tokens patterns or list
// e.g., export const specialTokenPatterns: RegExp[] = [/<\|endoftext\|>/];
export {}; 