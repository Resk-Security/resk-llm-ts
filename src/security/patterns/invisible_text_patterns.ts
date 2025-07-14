/**
 * Patterns pour détecter du texte invisible ou obfusqué (zero-width, whitespaces, etc.)
 */
export const invisibleTextPatterns: RegExp[] = [
  /\u200B|\u200C|\u200D|\u2060|\uFEFF/g, // Zero-width space, non-joiner, joiner, word joiner, BOM
  /\u202A|\u202B|\u202C|\u202D|\u202E/g, // LTR/RTL marks
  /\u00AD/g, // Soft hyphen
  /[\u2066-\u2069]/g, // LRM, RLM, FSI, PDI, etc.
  /\s{5,}/g, // Séquences longues d'espaces
]; 