/**
 * Système de persistance vectorielle pour bases de données externes
 * Support pour Pinecone, Weaviate, ChromaDB et autres
 */

import { EmbeddingFunction, VectorEntry, VectorMetadata, SimilarityResult, IVectorDatabase } from '../types';
import { randomUUID } from 'crypto';

export interface VectorStoreConfig {
    type: 'pinecone' | 'weaviate' | 'chromadb' | 'qdrant' | 'milvus' | 'custom';
    connectionConfig: Record<string, unknown>;
    embeddingFunction: EmbeddingFunction;
    similarityThreshold?: number;
    namespace?: string;
    indexName?: string;
    collectionName?: string;
    timeout?: number;
}

export interface VectorSearchOptions {
    k?: number;
    threshold?: number;
    filter?: Record<string, unknown>;
    namespace?: string;
}

/**
 * Interface abstraite pour les stores vectoriels
 */
export abstract class VectorStore implements IVectorDatabase {
    protected config: VectorStoreConfig;
    protected embeddingFn: EmbeddingFunction;
    protected similarityThreshold: number;

    constructor(config: VectorStoreConfig) {
        this.config = config;
        this.embeddingFn = config.embeddingFunction;
        this.similarityThreshold = config.similarityThreshold || 0.85;
    }

    abstract isEnabled(): boolean;
    abstract addTextEntry(text: string, metadata?: VectorMetadata): Promise<string | null>;
    abstract addEntry(vector: number[], metadata?: VectorMetadata): string | null;
    abstract searchSimilarText(text: string, k?: number, threshold?: number): Promise<SimilarityResult>;
    abstract searchSimilarVector(queryVector: number[], k?: number, threshold?: number): SimilarityResult;
    abstract detect(text: string): Promise<SimilarityResult>;

    // Méthodes communes
    protected abstract connect(): Promise<void>;
    protected abstract disconnect(): Promise<void>;
    public abstract healthCheck(): Promise<boolean>;

    /**
     * Test de connectivité
     */
    async testConnection(): Promise<boolean> {
        try {
            return await this.healthCheck();
        } catch (error) {
            console.error(`[${this.config.type}] Connection test failed:`, error);
            return false;
        }
    }
}

/**
 * Implémentation Pinecone
 */
export class PineconeVectorStore extends VectorStore {
    private client: any = null;
    private index: any = null;

    constructor(config: VectorStoreConfig) {
        super(config);
    }

    isEnabled(): boolean {
        return !!this.config.connectionConfig.apiKey && !!this.config.indexName;
    }

    async connect(): Promise<void> {
        if (this.client) return;

        try {
            // Dynamic import to avoid mandatory dependency
            throw new Error('Pinecone integration requires @pinecone-database/pinecone package. Run: npm install @pinecone-database/pinecone');
        } catch (error) {
            throw new Error(`Failed to connect to Pinecone: ${error}`);
        }
    }

    async disconnect(): Promise<void> {
        this.client = null;
        this.index = null;
    }

    async healthCheck(): Promise<boolean> {
        try {
            await this.connect();
            const stats = await this.index.describeIndexStats();
            return !!stats;
        } catch (error) {
            return false;
        }
    }

    async addTextEntry(text: string, metadata: VectorMetadata = {}): Promise<string | null> {
        try {
            await this.connect();
            const vector = await this.embeddingFn(text);
            return this.addEntry(vector, { ...metadata, text });
        } catch (error) {
            console.error('[Pinecone] Error adding text entry:', error);
            return null;
        }
    }

    addEntry(vector: number[], metadata: VectorMetadata = {}): string | null {
        try {
            const id = metadata.id?.toString() || randomUUID();
            
            // Pinecone upsert (async mais on ne wait pas pour compatibilité)
            this.index.upsert([{
                id,
                values: vector,
                metadata: {
                    ...metadata,
                    timestamp: Date.now(),
                    source: 'resk-llm-ts'
                }
            }], {
                namespace: this.config.namespace
            }).catch((error: any) => {
                console.error('[Pinecone] Error upserting vector:', error);
            });

            return id;
        } catch (error) {
            console.error('[Pinecone] Error adding entry:', error);
            return null;
        }
    }

    async searchSimilarText(text: string, k: number = 3, threshold?: number): Promise<SimilarityResult> {
        try {
            await this.connect();
            const queryVector = await this.embeddingFn(text);
            return this.searchSimilarVector(queryVector, k, threshold);
        } catch (error) {
            console.error('[Pinecone] Error searching similar text:', error);
            return { detected: false, max_similarity: 0, similar_entries: [] };
        }
    }

    searchSimilarVector(queryVector: number[], k: number = 3, threshold?: number): SimilarityResult {
        try {
            // Pinecone query (promesse mais on doit gérer sync/async)
            this.index.query({
                vector: queryVector,
                topK: k,
                includeMetadata: true,
                namespace: this.config.namespace
            });

            // Pour la compatibilité, on retourne un résultat par défaut
            // En pratique, il faudrait faire cette méthode async
            console.warn('[Pinecone] searchSimilarVector should be async for proper implementation');
            return { detected: false, max_similarity: 0, similar_entries: [] };
        } catch (error) {
            console.error('[Pinecone] Error searching similar vector:', error);
            return { detected: false, max_similarity: 0, similar_entries: [] };
        }
    }

    async detect(text: string): Promise<SimilarityResult> {
        try {
            await this.connect();
            const queryVector = await this.embeddingFn(text);
            
            const response = await this.index.query({
                vector: queryVector,
                topK: 1,
                includeMetadata: true,
                namespace: this.config.namespace
            });

            const matches = response.matches || [];
            const maxSimilarity = matches.length > 0 ? matches[0].score : 0;
            const detected = maxSimilarity >= this.similarityThreshold;

            const similarEntries: VectorEntry[] = matches
                .filter((match: any) => match.score >= this.similarityThreshold)
                .map((match: any) => ({
                    id: match.id,
                    vector: [], // Pinecone ne retourne pas les vecteurs par défaut
                    metadata: match.metadata || {}
                }));

            return {
                detected,
                max_similarity: maxSimilarity,
                similar_entries: similarEntries
            };
        } catch (error) {
            console.error('[Pinecone] Error detecting:', error);
            return { detected: false, max_similarity: 0, similar_entries: [] };
        }
    }
}

/**
 * Implémentation Weaviate
 */
export class WeaviateVectorStore extends VectorStore {
    private client: any = null;

    constructor(config: VectorStoreConfig) {
        super(config);
    }

    isEnabled(): boolean {
        return !!this.config.connectionConfig.scheme && !!this.config.connectionConfig.host;
    }

    async connect(): Promise<void> {
        if (this.client) return;

        try {
            // Dynamic import to avoid mandatory dependency
            throw new Error('Weaviate integration requires weaviate-ts-client package. Run: npm install weaviate-ts-client');
        } catch (error) {
            throw new Error(`Failed to connect to Weaviate: ${error}`);
        }
    }

    async disconnect(): Promise<void> {
        this.client = null;
    }

    async healthCheck(): Promise<boolean> {
        try {
            await this.connect();
            const response = await this.client.misc.liveChecker().do();
            return response === true;
        } catch (error) {
            return false;
        }
    }

    async addTextEntry(text: string, metadata: VectorMetadata = {}): Promise<string | null> {
        try {
            await this.connect();
            const vector = await this.embeddingFn(text);
            
            const id = metadata.id?.toString() || randomUUID();
            const className = this.config.collectionName || 'SecurityPattern';

            await this.client.data.creator()
                .withClassName(className)
                .withId(id)
                .withProperties({
                    text,
                    ...metadata,
                    timestamp: Date.now(),
                    source: 'resk-llm-ts'
                })
                .withVector(vector)
                .do();

            return id;
        } catch (error) {
            console.error('[Weaviate] Error adding text entry:', error);
            return null;
        }
    }

    addEntry(vector: number[], metadata: VectorMetadata = {}): string | null {
        try {
            const id = metadata.id?.toString() || randomUUID();
            const className = this.config.collectionName || 'SecurityPattern';

            // Weaviate create (async mais on ne wait pas pour compatibilité)
            this.client.data.creator()
                .withClassName(className)
                .withId(id)
                .withProperties({
                    ...metadata,
                    timestamp: Date.now(),
                    source: 'resk-llm-ts'
                })
                .withVector(vector)
                .do()
                .catch((error: any) => {
                    console.error('[Weaviate] Error creating object:', error);
                });

            return id;
        } catch (error) {
            console.error('[Weaviate] Error adding entry:', error);
            return null;
        }
    }

    async searchSimilarText(text: string, k: number = 3, threshold?: number): Promise<SimilarityResult> {
        try {
            await this.connect();
            const queryVector = await this.embeddingFn(text);
            
            const className = this.config.collectionName || 'SecurityPattern';
            const currentThreshold = threshold ?? this.similarityThreshold;

            const response = await this.client.graphql.get()
                .withClassName(className)
                .withFields('_additional { id certainty } text')
                .withNearVector({ vector: queryVector, certainty: currentThreshold })
                .withLimit(k)
                .do();

            const objects = response.data?.Get?.[className] || [];
            const maxSimilarity = objects.length > 0 ? objects[0]._additional.certainty : 0;
            const detected = maxSimilarity >= currentThreshold;

            const similarEntries: VectorEntry[] = objects.map((obj: any) => ({
                id: obj._additional.id,
                vector: [],
                metadata: {
                    text: obj.text,
                    similarity: obj._additional.certainty
                }
            }));

            return {
                detected,
                max_similarity: maxSimilarity,
                similar_entries: similarEntries
            };
        } catch (error) {
            console.error('[Weaviate] Error searching similar text:', error);
            return { detected: false, max_similarity: 0, similar_entries: [] };
        }
    }

    searchSimilarVector(queryVector: number[], k: number = 3, threshold?: number): SimilarityResult {
        console.warn('[Weaviate] searchSimilarVector should be async for proper implementation');
        return { detected: false, max_similarity: 0, similar_entries: [] };
    }

    async detect(text: string): Promise<SimilarityResult> {
        return this.searchSimilarText(text, 1, this.similarityThreshold);
    }
}

/**
 * Implémentation ChromaDB
 */
export class ChromaDBVectorStore extends VectorStore {
    private client: any = null;
    private collection: any = null;

    constructor(config: VectorStoreConfig) {
        super(config);
    }

    isEnabled(): boolean {
        return !!this.config.connectionConfig.path || !!this.config.connectionConfig.host;
    }

    async connect(): Promise<void> {
        if (this.client) return;

        try {
            // Dynamic import to avoid mandatory dependency
            throw new Error('ChromaDB integration requires chromadb package. Run: npm install chromadb');
        } catch (error) {
            throw new Error(`Failed to connect to ChromaDB: ${error}`);
        }
    }

    async disconnect(): Promise<void> {
        this.client = null;
        this.collection = null;
    }

    async healthCheck(): Promise<boolean> {
        try {
            await this.connect();
            const heartbeat = await this.client.heartbeat();
            return !!heartbeat;
        } catch (error) {
            return false;
        }
    }

    async addTextEntry(text: string, metadata: VectorMetadata = {}): Promise<string | null> {
        try {
            await this.connect();
            const vector = await this.embeddingFn(text);
            
            const id = metadata.id?.toString() || randomUUID();

            await this.collection.add({
                ids: [id],
                embeddings: [vector],
                documents: [text],
                metadatas: [{
                    ...metadata,
                    timestamp: Date.now(),
                    source: 'resk-llm-ts'
                }]
            });

            return id;
        } catch (error) {
            console.error('[ChromaDB] Error adding text entry:', error);
            return null;
        }
    }

    addEntry(vector: number[], metadata: VectorMetadata = {}): string | null {
        try {
            const id = metadata.id?.toString() || randomUUID();

            // ChromaDB add (async mais on ne wait pas pour compatibilité)
            this.collection.add({
                ids: [id],
                embeddings: [vector],
                metadatas: [{
                    ...metadata,
                    timestamp: Date.now(),
                    source: 'resk-llm-ts'
                }]
            }).catch((error: any) => {
                console.error('[ChromaDB] Error adding vector:', error);
            });

            return id;
        } catch (error) {
            console.error('[ChromaDB] Error adding entry:', error);
            return null;
        }
    }

    async searchSimilarText(text: string, k: number = 3, threshold?: number): Promise<SimilarityResult> {
        try {
            await this.connect();
            const queryVector = await this.embeddingFn(text);
            
            const response = await this.collection.query({
                queryEmbeddings: [queryVector],
                nResults: k,
                includeDistances: true,
                includeDocuments: true,
                includeMetadatas: true
            });

            const distances = response.distances?.[0] || [];
            const documents = response.documents?.[0] || [];
            const metadatas = response.metadatas?.[0] || [];
            const ids = response.ids?.[0] || [];

            const currentThreshold = threshold ?? this.similarityThreshold;
            
            // ChromaDB retourne des distances (plus faible = plus similaire)
            // Convertir en similarité (1 - distance)
            const similarities = distances.map((dist: number) => 1 - dist);
            const maxSimilarity = similarities.length > 0 ? Math.max(...similarities) : 0;
            const detected = maxSimilarity >= currentThreshold;

            const similarEntries: VectorEntry[] = [];
            for (let i = 0; i < ids.length; i++) {
                const similarity = similarities[i];
                if (similarity >= currentThreshold) {
                    similarEntries.push({
                        id: ids[i],
                        vector: [],
                        metadata: {
                            ...metadatas[i],
                            document: documents[i],
                            similarity: similarity
                        }
                    });
                }
            }

            return {
                detected,
                max_similarity: maxSimilarity,
                similar_entries: similarEntries
            };
        } catch (error) {
            console.error('[ChromaDB] Error searching similar text:', error);
            return { detected: false, max_similarity: 0, similar_entries: [] };
        }
    }

    searchSimilarVector(queryVector: number[], k: number = 3, threshold?: number): SimilarityResult {
        console.warn('[ChromaDB] searchSimilarVector should be async for proper implementation');
        return { detected: false, max_similarity: 0, similar_entries: [] };
    }

    async detect(text: string): Promise<SimilarityResult> {
        return this.searchSimilarText(text, 1, this.similarityThreshold);
    }
}

/**
 * Factory pour créer des vector stores
 */
export class VectorStoreFactory {
    static createVectorStore(config: VectorStoreConfig): VectorStore {
        switch (config.type) {
            case 'pinecone':
                return new PineconeVectorStore(config);
            case 'weaviate':
                return new WeaviateVectorStore(config);
            case 'chromadb':
                return new ChromaDBVectorStore(config);
            default:
                throw new Error(`Unsupported vector store type: ${config.type}`);
        }
    }

    static getSupportedStores(): string[] {
        return ['pinecone', 'weaviate', 'chromadb'];
    }

    /**
     * Teste la disponibilité des dépendances pour un type de store
     */
    static async testDependencies(storeType: string): Promise<boolean> {
        try {
            switch (storeType) {
                case 'pinecone':
                    throw new Error('Pinecone package not installed. Run: npm install @pinecone-database/pinecone');
                case 'weaviate':
                    throw new Error('Weaviate package not installed. Run: npm install weaviate-ts-client');
                case 'chromadb':
                    throw new Error('ChromaDB package not installed. Run: npm install chromadb');
                case 'in-memory':
                    return true;
                default:
                    return false;
            }
        } catch (error) {
            return false;
        }
    }
}

/**
 * Utilitaires pour la migration et la synchronisation
 */
export class VectorStoreUtils {
    /**
     * Migre des données d'un store vers un autre
     */
    static async migrateData(
        sourceStore: VectorStore,
        targetStore: VectorStore,
        batchSize: number = 100
    ): Promise<number> {
        console.log('[VectorStoreUtils] Starting data migration...');
        let migratedCount = 0;

        try {
            // Implémentation simplifiée - en pratique il faudrait paginer
            console.warn('[VectorStoreUtils] Migration implementation is simplified');
            
            // TODO: Implémenter la migration complète avec pagination
            // - Lire les données du store source
            // - Les transférer vers le store cible par batch
            // - Gérer les erreurs et retry
            
            return migratedCount;
        } catch (error) {
            console.error('[VectorStoreUtils] Migration failed:', error);
            throw error;
        }
    }

    /**
     * Synchronise deux stores vectoriels
     */
    static async syncStores(
        primaryStore: VectorStore,
        secondaryStore: VectorStore
    ): Promise<{ synced: number; errors: number }> {
        console.log('[VectorStoreUtils] Starting store synchronization...');
        
        // TODO: Implémenter la synchronisation
        // - Comparer les IDs et timestamps
        // - Synchroniser les différences
        // - Résoudre les conflits
        
        return { synced: 0, errors: 0 };
    }

    /**
     * Optimise un store vectoriel (nettoyage, indexation)
     */
    static async optimizeStore(store: VectorStore): Promise<void> {
        console.log('[VectorStoreUtils] Optimizing vector store...');
        
        // TODO: Implémenter l'optimisation
        // - Supprimer les entrées obsolètes
        // - Réindexer si nécessaire
        // - Compacter les données
    }
}