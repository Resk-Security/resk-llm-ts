/**
 * Enhanced patterns for detecting malicious URLs, phishing attempts, and suspicious links.
 * Includes obfuscation-resistant patterns.
 * 
 * WARNING: URL-based detection has limitations against sophisticated obfuscation.
 * Should be combined with:
 * - Domain reputation checking
 * - Real-time URL scanning
 * - Context analysis
 * - Safebrowsing APIs
 */

// Standard malicious URL patterns
export const maliciousUrlPatterns: RegExp[] = [
  // URL shorteners (enhanced with obfuscation variants)
  /(?:https?|hxxps?|h\[tt\]ps?):\/\/(?:\w+\.)?(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly|rebrand\.ly|is\.gd|cutt\.ly|short\.link|tiny\.cc)\//i,
  
  // Suspicious TLDs (enhanced)
  /(?:https?|hxxps?|h\[tt\]ps?):\/\/[\w.-]*\.(?:ru|cn|su|tk|ml|ga|cf|gq|xyz|top|pw|work|zip|click|link|rest|fit|men|loan|date|review|trade|stream|download|exe|scr|bat|vbs)\b/i,
  
  // Phishing paths (enhanced)
  /(?:https?|hxxps?|h\[tt\]ps?):\/\/[\w.-]*\/(?:login|secure|update|verify|account|reset|bank|paypal|wallet|crypto|bitcoin|gift|prize|free|bonus|urgent|suspended|confirm|activation|security|support|help-desk)/i,
  
  // IP addresses instead of domains (suspicious)
  /(?:https?|hxxps?|h\[tt\]ps?):\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\//,
  
  // Suspicious domain patterns (more specific to avoid false positives)
  /(?:https?|hxxps?|h\[tt\]ps?):\/\/(?![\w.-]*\.(?:gov|gouv|edu|fr|com|org|net|io|ai|mil|int|google|facebook|microsoft|apple|amazon|github|stackoverflow|wikipedia)\b)[\w.-]+\.(?:tk|ml|ga|cf|gq|xyz|top|pw|work|zip|click|link)\b/i,
];

// Obfuscated URL patterns
export const obfuscatedUrlPatterns: RegExp[] = [
  // Bracket obfuscation: http://bit[.]ly/malicious
  /h[tx]{2,}ps?:\/\/[\w.-]*\[\.\][\w.-]*\//i,
  
  // Defanged URLs: hxxp://bit.ly/malicious
  /hxx[pt]s?:\/\/[\w.-]+\//i,
  
  // Mixed bracket and character substitution
  /h[?[tx]{2,}]?ps?:\/\/[\w[\].-]+\//i,
  
  // URL with excessive obfuscation
  /(?:h[?t{2,}]?p[?s?]?|hxx[pt]s?):\/\/[\w[\].-]+\//i,
  
  // Space separation: http ://bit .ly/malicious  
  /h\s*t{2,}\s*p\s*s?\s*:\s*\/\s*\/\s*[\w\s.-]+\//i,
  
  // Unicode/homoglyph domains
  /https?:\/\/[\w.-]*[а-я][\w.-]*\//i, // Cyrillic chars
  /https?:\/\/[\w.-]*[αβγδεζηθικλμνξοπρστυφχψω][\w.-]*\//i, // Greek chars
];

// Suspicious domain name patterns
export const suspiciousDomainPatterns: RegExp[] = [
  // Typosquatting common sites
  /(?:goog1e|g00gle|googIe|amaz0n|amаzon|paypaI|pаypal|micr0soft|microsooft|app1e|аpple|faceb00k|fаcebook)\.[\w.-]+/i,
  
  // Suspicious lookalike domains
  /(?:secure-|security-|support-|help-|update-|verify-|confirm-|account-|login-|bank-|wallet-)[\w.-]+/i,
  
  // Domains with excessive hyphens or numbers
  /[\w.-]*-{3,}[\w.-]*\.[\w.-]+/i,
  /[\w.-]*\d{3,}[\w.-]*\.[\w.-]+/i,
];

// All malicious URL patterns combined
export const allMaliciousUrlPatterns: RegExp[] = [
  ...maliciousUrlPatterns,
  ...obfuscatedUrlPatterns,
  ...suspiciousDomainPatterns,
]; 