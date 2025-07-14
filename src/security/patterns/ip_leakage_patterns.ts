/**
 * Patterns pour détecter des fuites d'adresses IP (IPv4 et IPv6, y compris privées)
 */
export const ipLeakagePatterns: RegExp[] = [
  /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g, // IPv4
  /\b([a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b/g, // IPv6
  /\b10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b/g, // IPv4 privé
  /\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b/g, // IPv4 privé
  /\b172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}\b/g, // IPv4 privé
]; 