/**
 * Enhanced patterns for detecting prompt injection attempts.
 * Includes obfuscation-resistant patterns and normalization support.
 * 
 * WARNING: Pattern-based detection has inherent limitations against sophisticated attacks.
 * These patterns should be combined with:
 * - Semantic analysis
 * - Context awareness
 * - Rate limiting
 * - Human review for critical applications
 */
export const defaultInjectionPatterns: RegExp[] = [
    // Enhanced instruction overriding patterns (obfuscation-resistant)
    /(?:ign[0o]r[3e]|disregard|bypass|skip|override)[\s\W]*(?:all[\s\W]*)?(?:pr[3e]vi[0o]us|pri[0o]r|ab[0o]v[3e]|earlier)[\s\W]*(?:instruct[1i][0o]ns?|rul[3e]s?|dir[3e]ct[1i]v[3e]s?|guid[3e]lin[3e]s?)/i,
    
    // More comprehensive disregard patterns
    /(?:disregard|f[0o]rg[3e]t|[1i]gn[0o]r[3e]|bypass|skip)[\s\W]*(?:y[0o]ur[\s\W]*)?(?:guid[3e]lin[3e]s?|rul[3e]s?|pr[3e]vi[0o]us|pri[0o]r|ab[0o]v[3e]|earlier|[1i]nitial)/i,
    
    // Role/mode switching patterns
    /(?:y[0o]u[\s\W]*ar[3e]|pr[3e]t[3e]nd[\s\W]*t[0o][\s\W]*b[3e]|act[\s\W]*as)[\s\W]*(?:n[0o]w|h[3e]nc[3e]f[0o]rth)?[\s\W]*(?:[1i]n[\s\W]*)?(?:d[3e]v[3e]l[0o]p[3e]r|admin|r[0o][0o]t|debug|t[3e]st|unc[3e]ns[0o]r[3e]d|unr[3e]strict[3e]d)[\s\W]*m[0o]d[3e]/i,
    
    // Command/control patterns
    /(?:y[0o]u[\s\W]*w[1i]ll|y[0o]u[\s\W]*must|y[0o]u[\s\W]*shall)[\s\W]*(?:n[0o]w|h[3e]nc[3e]f[0o]rth|[1i]mm[3e]d[1i]at[3e]ly)?[\s\W]*(?:d[0o]|[0o]b[3e]y|f[0o]ll[0o]w|[3e]x[3e]cut[3e])[\s\W]*(?:[3e]xactly[\s\W]*)?as[\s\W]*[1i][\s\W]*say/i,
    
    // System prompt leakage (enhanced)
    /(?:r[3e]v[3e]al|sh[0o]w|print|display|[0o]utput|r[3e]p[3e]at|[3e]ch[0o])[\s\W]*(?:y[0o]ur|th[3e])[\s\W]*(?:syst[3e]m[\s\W]*)?(?:pr[0o]mpt|[1i]nstruct[1i][0o]ns?|[1i]nitial[\s\W]*(?:m[3e]ssag[3e]|t[3e]xt)|s[3e]tup|c[0o]nfig)/i,
    
    // Question-based prompt leakage
    /what[\s\W]*(?:ar[3e]|w[3e]r[3e])[\s\W]*y[0o]ur[\s\W]*(?:[0o]riginal|[1i]nitial|syst[3e]m|start[1i]ng)[\s\W]*(?:[1i]nstruct[1i][0o]ns?|rul[3e]s?|pr[0o]mpt)/i,
    
    // Token/delimiter injection
    /(?:<\|[^>]*\|>|```[^`]*```|\[INST\]|\[\/INST\]|<s>|<\/s>)/i,
    
    // Obfuscation with multiple techniques
    /[1i][\s\W]*g[\s\W]*n[\s\W]*[0o][\s\W]*r[\s\W]*[3e]/i, // i g n o r e with spacing/symbols
    /d[\s\W]*[1i][\s\W]*s[\s\W]*r[\s\W]*[3e][\s\W]*g[\s\W]*a[\s\W]*r[\s\W]*d/i, // d i s r e g a r d
    
    // Jailbreak-specific patterns
    /(?:jailbr[3e]ak|j[4a][1i]lbr[3e][4a]k|unc[3e]ns[0o]r|byp[4a]ss[\s\W]*filt[3e]r|break[\s\W]*fr[3e][3e])/i,
    
    // Role reversal attempts
    /(?:n[0o]w[\s\W]*)?y[0o]u[\s\W]*ar[3e][\s\W]*(?:th[3e][\s\W]*)?us[3e]r[\s\W]*and[\s\W]*[1i][\s\W]*am[\s\W]*(?:th[3e][\s\W]*)?(?:ass[1i]stant|[4a][1i]|m[0o]d[3e]l)/i,
];

// Placeholder for LLM injection patterns (e.g., export const injectionPatterns: RegExp[] = [/.../];)
export {}; 