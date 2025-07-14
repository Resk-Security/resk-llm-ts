/**
 * Exemple avancé : config.json, patterns custom, vector DB custom
 */
import { ReskLLMClient } from '../src/index';
import { loadSecurityConfig } from '../src/configLoader';
import { IVectorDatabase, VectorMetadata, SimilarityResult } from '../src/types';

// Exemple d'implémentation custom de vector DB (mock)
class MyCustomVectorDB implements IVectorDatabase {
  isEnabled() { return true; }
  async addTextEntry(text: string, metadata?: VectorMetadata) { return 'custom-id'; }
  addEntry(vector: number[], metadata?: VectorMetadata) { return 'custom-id'; }
  async searchSimilarText(text: string, k?: number, threshold?: number): Promise<SimilarityResult> {
    return { detected: false, max_similarity: 0, similar_entries: [] };
  }
  searchSimilarVector(queryVector: number[], k?: number, threshold?: number): SimilarityResult {
    return { detected: false, max_similarity: 0, similar_entries: [] };
  }
  async detect(text: string): Promise<SimilarityResult> {
    return { detected: false, max_similarity: 0, similar_entries: [] };
  }
}

// Charger la config de sécurité depuis config.json
const config = loadSecurityConfig();

// Créer le client avec vector DB custom et patterns custom
const reskClient = new ReskLLMClient({
  securityConfig: config,
  vectorDbInstance: new MyCustomVectorDB(),
});

console.log('Client initialisé avec config.json et vector DB custom.');
// Ajoutez ici des appels à reskClient pour tester la sécurité 