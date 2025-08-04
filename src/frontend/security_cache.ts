/**
 * Système de cache haute performance pour les validations de sécurité
 * Optimise les performances en évitant les re-calculs sur des contenus similaires
 */

export interface CacheConfig {
    enabled: boolean;
    maxSize: number;
    ttl: number; // Time to live en millisecondes
    strategy: 'lru' | 'lfu' | 'ttl'; // Least Recently Used, Least Frequently Used, Time To Live
    compression?: boolean;
    persistToStorage?: boolean;
}

interface CacheEntry<T> {
    value: T;
    timestamp: number;
    accessCount: number;
    lastAccess: number;
    size: number;
}

interface CacheStats {
    hits: number;
    misses: number;
    evictions: number;
    totalSize: number;
    hitRate: number;
    averageAccessTime: number;
}

/**
 * Cache haute performance avec différentes stratégies d'éviction
 */
export class SecurityCache {
    private cache = new Map<string, CacheEntry<any>>();
    private config: Required<CacheConfig>;
    private cleanupInterval: NodeJS.Timeout | null = null;
    private stats: CacheStats = {
        hits: 0,
        misses: 0,
        evictions: 0,
        totalSize: 0,
        hitRate: 0,
        averageAccessTime: 0
    };
    private accessTimes: number[] = [];

    constructor(config: Partial<CacheConfig> = {}) {
        this.config = {
            enabled: true,
            maxSize: 1000,
            ttl: 300000, // 5 minutes
            strategy: 'lru',
            compression: false,
            persistToStorage: false,
            ...config
        };

        // Initialiser depuis le storage si configuré
        if (this.config.persistToStorage && typeof localStorage !== 'undefined') {
            this.loadFromStorage();
        }

        // Nettoyage périodique
        this.cleanupInterval = setInterval(() => this.cleanup(), this.config.ttl / 2);
    }

    /**
     * Récupération d'une valeur du cache
     */
    get<T>(key: string): T | null {
        if (!this.config.enabled) return null;

        const start = performance.now();
        const entry = this.cache.get(key);

        if (!entry) {
            this.stats.misses++;
            return null;
        }

        // Vérifier TTL
        if (this.isExpired(entry)) {
            this.cache.delete(key);
            this.stats.misses++;
            this.stats.evictions++;
            return null;
        }

        // Mettre à jour les statistiques d'accès
        entry.lastAccess = Date.now();
        entry.accessCount++;
        this.stats.hits++;

        // Enregistrer le temps d'accès
        const accessTime = performance.now() - start;
        this.accessTimes.push(accessTime);
        if (this.accessTimes.length > 100) {
            this.accessTimes.shift(); // Keep only the last 100
        }

        this.updateHitRate();
        
        const value = this.config.compression ? this.decompress(entry.value) : entry.value;
        return value as T;
    }

    /**
     * Stockage d'une valeur dans le cache
     */
    set<T>(key: string, value: T): void {
        if (!this.config.enabled) return;

        // Préparer la valeur
        const processedValue = this.config.compression ? this.compress(value) : value;
        const size = this.calculateSize(processedValue);

        // Vérifier si on doit faire de la place
        if (this.cache.size >= this.config.maxSize) {
            this.evict();
        }

        // Create entry
        const entry: CacheEntry<T> = {
            value: processedValue as T,
            timestamp: Date.now(),
            accessCount: 1,
            lastAccess: Date.now(),
            size
        };

        this.cache.set(key, entry);
        this.stats.totalSize += size;

        // Persister si configuré
        if (this.config.persistToStorage) {
            this.saveToStorage();
        }
    }

    /**
     * Vérification d'existence d'une clé
     */
    has(key: string): boolean {
        if (!this.config.enabled) return false;
        
        const entry = this.cache.get(key);
        if (!entry) return false;
        
        return !this.isExpired(entry);
    }

    /**
     * Suppression d'une entrée
     */
    delete(key: string): boolean {
        const entry = this.cache.get(key);
        if (entry) {
            this.stats.totalSize -= entry.size;
        }
        return this.cache.delete(key);
    }

    /**
     * Nettoyage complet du cache
     */
    clear(): void {
        this.cache.clear();
        this.stats.totalSize = 0;
        this.stats.evictions = 0;
        
        // Nettoyer le timer de nettoyage
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
        }
        
        if (this.config.persistToStorage && typeof localStorage !== 'undefined') {
            localStorage.removeItem('resk_security_cache');
        }
    }

    /**
     * Statistiques du cache
     */
    getStats(): CacheStats {
        this.updateHitRate();
        this.updateAverageAccessTime();
        return { ...this.stats };
    }

    /**
     * Nettoyage des entrées expirées
     */
    private cleanup(): void {
        const now = Date.now();
        let cleaned = 0;

        for (const [key, entry] of this.cache.entries()) {
            if (this.isExpired(entry)) {
                this.stats.totalSize -= entry.size;
                this.cache.delete(key);
                cleaned++;
            }
        }

        if (cleaned > 0) {
            this.stats.evictions += cleaned;
            console.debug(`[SecurityCache] Cleaned ${cleaned} expired entries`);
        }
    }

    /**
     * Vérification d'expiration
     */
    private isExpired(entry: CacheEntry<any>): boolean {
        return Date.now() - entry.timestamp > this.config.ttl;
    }

    /**
     * Éviction selon la stratégie configurée
     */
    private evict(): void {
        let keyToEvict: string | null = null;

        switch (this.config.strategy) {
            case 'lru':
                keyToEvict = this.findLRU();
                break;
            case 'lfu':
                keyToEvict = this.findLFU();
                break;
            case 'ttl':
                keyToEvict = this.findOldest();
                break;
        }

        if (keyToEvict) {
            const entry = this.cache.get(keyToEvict);
            if (entry) {
                this.stats.totalSize -= entry.size;
            }
            this.cache.delete(keyToEvict);
            this.stats.evictions++;
        }
    }

    /**
     * Trouve l'entrée Least Recently Used
     */
    private findLRU(): string | null {
        let oldestKey: string | null = null;
        let oldestTime = Infinity;

        for (const [key, entry] of this.cache.entries()) {
            if (entry.lastAccess < oldestTime) {
                oldestTime = entry.lastAccess;
                oldestKey = key;
            }
        }

        return oldestKey;
    }

    /**
     * Trouve l'entrée Least Frequently Used
     */
    private findLFU(): string | null {
        let leastUsedKey: string | null = null;
        let leastCount = Infinity;

        for (const [key, entry] of this.cache.entries()) {
            if (entry.accessCount < leastCount) {
                leastCount = entry.accessCount;
                leastUsedKey = key;
            }
        }

        return leastUsedKey;
    }

    /**
     * Trouve l'entrée la plus ancienne
     */
    private findOldest(): string | null {
        let oldestKey: string | null = null;
        let oldestTime = Infinity;

        for (const [key, entry] of this.cache.entries()) {
            if (entry.timestamp < oldestTime) {
                oldestTime = entry.timestamp;
                oldestKey = key;
            }
        }

        return oldestKey;
    }

    /**
     * Calcul approximatif de la taille
     */
    private calculateSize(value: any): number {
        try {
            return JSON.stringify(value).length * 2; // Approximation UTF-16
        } catch {
            return 1000; // Taille par défaut si le calcul échoue
        }
    }

    /**
     * Compression simple (base64)
     */
    private compress(value: any): string {
        if (!this.config.compression) return value;
        
        try {
            const json = JSON.stringify(value);
            return btoa(json);
        } catch {
            return value;
        }
    }

    /**
     * Décompression
     */
    private decompress(value: string): any {
        if (!this.config.compression) return value;
        
        try {
            const json = atob(value);
            return JSON.parse(json);
        } catch {
            return value;
        }
    }

    /**
     * Mise à jour du taux de réussite
     */
    private updateHitRate(): void {
        const total = this.stats.hits + this.stats.misses;
        this.stats.hitRate = total > 0 ? this.stats.hits / total : 0;
    }

    /**
     * Mise à jour du temps d'accès moyen
     */
    private updateAverageAccessTime(): void {
        if (this.accessTimes.length > 0) {
            const sum = this.accessTimes.reduce((a, b) => a + b, 0);
            this.stats.averageAccessTime = sum / this.accessTimes.length;
        }
    }

    /**
     * Sauvegarde vers localStorage
     */
    private saveToStorage(): void {
        if (typeof localStorage === 'undefined') return;

        try {
            const data = {
                cache: Array.from(this.cache.entries()),
                stats: this.stats,
                timestamp: Date.now()
            };
            localStorage.setItem('resk_security_cache', JSON.stringify(data));
        } catch (error) {
            console.warn('[SecurityCache] Failed to save to localStorage:', error);
        }
    }

    /**
     * Chargement depuis localStorage
     */
    private loadFromStorage(): void {
        if (typeof localStorage === 'undefined') return;

        try {
            const stored = localStorage.getItem('resk_security_cache');
            if (!stored) return;

            const data = JSON.parse(stored);
            
            // Vérifier que les données ne sont pas trop anciennes
            if (Date.now() - data.timestamp > this.config.ttl * 2) {
                localStorage.removeItem('resk_security_cache');
                return;
            }

            // Restaurer le cache
            this.cache = new Map(data.cache);
            this.stats = { ...this.stats, ...data.stats };
            
            console.debug('[SecurityCache] Loaded from localStorage');
        } catch (error) {
            console.warn('[SecurityCache] Failed to load from localStorage:', error);
            localStorage.removeItem('resk_security_cache');
        }
    }

    /**
     * Préchargement intelligent basé sur les patterns
     */
    preload(patterns: string[]): void {
        // Pré-calculer les validations pour des patterns communs
        console.debug(`[SecurityCache] Preloading ${patterns.length} patterns`);
        // Implementation détaillée selon les besoins
    }

    /**
     * Optimisation basée sur l'utilisation
     */
    optimize(): void {
        // Ajuster la stratégie d'éviction selon les patterns d'utilisation
        if (this.stats.hitRate < 0.3 && this.config.strategy !== 'lfu') {
            console.debug('[SecurityCache] Switching to LFU strategy due to low hit rate');
            this.config.strategy = 'lfu';
        }
    }
}