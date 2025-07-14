/**
 * Patterns pour détecter des tentatives de doxxing (adresses, noms, réseaux sociaux, etc.)
 * À compléter selon la politique de sécurité.
 */
export const doxxingPatterns: RegExp[] = [
  /\b\d{1,4} ?(rue|avenue|boulevard|impasse|allée|chemin|place)\b/i, // Adresse FR
  /\b\d{1,4} ?(street|st\.|ave|avenue|road|rd\.|blvd|boulevard|lane|ln\.|drive|dr\.|court|ct\.|way)\b/i, // Adresse EN
  /@([A-Za-z0-9_]{3,30})/g, // Handle Twitter/Instagram
  /facebook\.com\//i, // Lien Facebook
  /linkedin\.com\//i, // Lien LinkedIn
  /snapchat\.com\//i, // Lien Snapchat
  /discord(?:app)?\.com\//i, // Discord
  /tiktok\.com\//i, // TikTok
  /\bnom[:=] ?[A-Za-zÀ-ÿ' -]{2,}/i, // "nom: ..." (FR)
  /\bname[:=] ?[A-Za-z' -]{2,}/i, // "name: ..." (EN)
]; 