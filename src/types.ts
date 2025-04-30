/**
 * Represents a function that takes a string and returns its vector embedding.
 */
export type EmbeddingFunction = (text: string) => Promise<number[]>;

/**
 * Represents metadata associated with a vector entry.
 */
export interface VectorMetadata {
    id?: string | number;
    [key: string]: any; // Allow arbitrary metadata
}

/**
 * Represents a single entry in the vector database.
 */
export interface VectorEntry {
    id: string; // Unique identifier for the entry
    vector: number[];
    metadata: VectorMetadata;
}

/**
 * Result of a similarity search or detection.
 */
export interface SimilarityResult {
    detected: boolean;
    max_similarity: number;
    similar_entries: VectorEntry[];
} 