/**
 * Patterns pour détecter des URLs malveillantes ou suspectes (phishing, raccourcisseurs, etc.)
 */
export const maliciousUrlPatterns: RegExp[] = [
  /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly|rebrand\.ly|is\.gd|cutt\.ly)\//i, // Raccourcisseurs
  /https?:\/\/(?![\w.-]*\.(gov|gouv|edu|fr|com|org|net|io|ai)\b)[\w.-]+\.[a-z]{2,}/i, // Domaines exotiques
  /https?:\/\/[\w.-]*\.(ru|cn|su|tk|ml|ga|cf|gq|xyz|top|pw|work|zip|click|link|rest|fit|men|loan|date|review|trade|stream|download)\b/i, // TLDs à risque
  /https?:\/\/[\w.-]*\/(login|secure|update|verify|account|reset|bank|paypal|wallet|crypto|bitcoin|gift|prize|free|bonus)/i, // Chemins suspects
]; 