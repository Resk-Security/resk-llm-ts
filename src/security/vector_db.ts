import { SecurityFeatureConfig } from "../index";
import { EmbeddingFunction, VectorEntry, VectorMetadata, SimilarityResult } from "../types";
import { randomUUID } from 'crypto'; // For generating unique IDs
import { dot, norm, number } from 'mathjs'; // Keep used imports

export interface VectorDBConfig extends SecurityFeatureConfig {
    embeddingFunction: EmbeddingFunction;
    similarityThreshold?: number;
    // In a real implementation, add connection details, collection names, etc.
}

/**
 * Calculates the cosine similarity between two vectors.
 * Vectors must be of the same length.
 */
function cosineSimilarity(vecA: number[], vecB: number[]): number {
    if (vecA.length !== vecB.length || vecA.length === 0) {
        return 0; // Or throw an error, depending on desired behavior
    }
    const dotProduct = dot(vecA, vecB);
    const normA = norm(vecA) as number; // Cast needed due to mathjs types
    const normB = norm(vecB) as number;
    
    if (normA === 0 || normB === 0) {
        return 0; // Avoid division by zero
    }
    
    // Ensure result is clamped between -1 and 1 due to potential floating point inaccuracies
    const similarity = dotProduct / (normA * normB);
    return Math.max(-1, Math.min(1, number(similarity))); // Ensure it's a standard number
}

/**
 * A basic in-memory vector database implementation.
 * 
 * WARNING: This is for demonstration purposes ONLY. It is not efficient for
 * large datasets and lacks persistence. Use a dedicated vector database
 * (e.g., LanceDB, ChromaDB, Pinecone, Weaviate) in production.
 */
export class VectorDatabase {
    private config: VectorDBConfig;
    private entries: VectorEntry[] = [];
    private embeddingFn: EmbeddingFunction;
    private similarityThreshold: number;

    constructor(config: VectorDBConfig) {
        // Separate the base 'enabled' flag from the specific DB config
        const { enabled, ...dbSpecificConfig } = config;

        // Apply defaults, then override with user config
        this.config = {
            // Default enabled state - can be overridden by config.enabled
            enabled: enabled !== undefined ? enabled : true, 
            similarityThreshold: 0.85, // Default threshold
            // Apply the rest of the user's DB-specific config
            ...dbSpecificConfig,
            // Ensure embeddingFunction is present after merge
            embeddingFunction: config.embeddingFunction 
        };

        // Ensure embedding function is provided if the feature is enabled
        if (this.config.enabled && !this.config.embeddingFunction) {
            throw new Error("VectorDatabase is enabled but requires an embeddingFunction.");
        }
        // Assign after validation
        this.embeddingFn = this.config.embeddingFunction!;

        // Ensure threshold is non-null after merge
        this.similarityThreshold = this.config.similarityThreshold!;

        // Only warn if the feature is actually enabled
        if (this.config.enabled) {
             console.warn("Using basic in-memory VectorDatabase. NOT suitable for production.")
        }
    }

    /**
     * Checks if the Vector Database feature is configured to be enabled.
     */
    public isEnabled(): boolean {
        return this.config.enabled;
    }

    /**
     * Updates the similarity threshold used for detection.
     * Value should be in the range [0, 1].
     */
    public setSimilarityThreshold(threshold: number): void {
        if (Number.isNaN(threshold) || threshold < 0 || threshold > 1) {
            throw new Error("Similarity threshold must be a number between 0 and 1.");
        }
        this.similarityThreshold = threshold;
        this.config.similarityThreshold = threshold;
    }

    /**
     * Adds a text entry to the database after generating its embedding.
     * @param text The text content to add.
     * @param metadata Optional metadata to associate with the entry.
     * @returns The ID of the newly added entry, or null if disabled.
     */
    async addTextEntry(text: string, metadata: VectorMetadata = {}): Promise<string | null> {
        if (!this.config.enabled) return null;
        try {
            const vector = await this.embeddingFn(text);
            return this.addEntry(vector, metadata);
        } catch (error) {
            console.error("Error adding text entry to Vector DB:", error);
            return null;
        }
    }

    /**
     * Adds a pre-computed vector entry to the database.
     * @param vector The vector embedding.
     * @param metadata Optional metadata to associate with the entry.
     * @returns The ID of the newly added entry, or null if disabled.
     */
    addEntry(vector: number[], metadata: VectorMetadata = {}): string | null {
        if (!this.config.enabled) return null;
        const id = metadata.id?.toString() || randomUUID();
        const entry: VectorEntry = {
            id: id,
            vector: vector,
            metadata: { ...metadata, id: id } // Ensure ID is in metadata
        };
        this.entries.push(entry);
        // console.log(`Added vector entry ${id}`);
        return id;
    }

    /**
     * Searches for entries similar to the given text.
     * @param text The query text.
     * @param k The maximum number of similar entries to return.
     * @param threshold Override the default similarity threshold.
     * @returns A SimilarityResult object.
     */
    async searchSimilarText(text: string, k: number = 3, threshold?: number): Promise<SimilarityResult> {
        if (!this.config.enabled) return { detected: false, max_similarity: 0, similar_entries: [] };
        try {
            const queryVector = await this.embeddingFn(text);
            return this.searchSimilarVector(queryVector, k, threshold);
        } catch (error) {
             console.error("Error searching similar text in Vector DB:", error);
             return { detected: false, max_similarity: 0, similar_entries: [] };
        }
    }

    /**
     * Searches for entries similar to the given vector.
     * @param queryVector The query vector.
     * @param k The maximum number of similar entries to return.
     * @param threshold Override the default similarity threshold.
     * @returns A SimilarityResult object.
     */
    searchSimilarVector(queryVector: number[], k: number = 3, threshold?: number): SimilarityResult {
        const currentThreshold = threshold ?? this.similarityThreshold;
        if (!this.config.enabled || this.entries.length === 0) {
            return { detected: false, max_similarity: 0, similar_entries: [] };
        }

        const similarities: { entry: VectorEntry; similarity: number }[] = [];
        for (const entry of this.entries) {
            const similarity = cosineSimilarity(queryVector, entry.vector);
            if (similarity >= currentThreshold) {
                similarities.push({ entry, similarity });
            }
        }

        // Sort by similarity descending
        similarities.sort((a, b) => b.similarity - a.similarity);

        const topKEntries = similarities.slice(0, k).map(s => s.entry);
        const maxSimilarity = similarities.length > 0 ? similarities[0].similarity : 0;

        return {
            detected: topKEntries.length > 0,
            max_similarity: maxSimilarity,
            similar_entries: topKEntries,
        };
    }

     /**
     * Convenience method specifically for detecting potential attacks based on similarity.
     * Uses the configured similarity threshold.
     * @param text The text to check.
     * @returns A SimilarityResult object.
     */
    async detect(text: string): Promise<SimilarityResult> {
         if (!this.config.enabled) return { detected: false, max_similarity: 0, similar_entries: [] };
         try {
            const queryVector = await this.embeddingFn(text);
            return this.searchSimilarVector(queryVector, 1, this.similarityThreshold); // Find top 1 above threshold
         } catch (error) {
            console.error("Error during detection in Vector DB:", error);
            return { detected: false, max_similarity: 0, similar_entries: [] };
        }
    }
} 