import fs from 'fs';
import path from 'path';
import { ReskSecurityConfig } from './types';

/**
 * Charge le fichier config.json à la racine du projet.
 * Retourne un objet ReskSecurityConfig ou undefined si absent.
 */
export function loadSecurityConfig(): ReskSecurityConfig | undefined {
  const configPath = path.resolve(process.cwd(), 'config.json');
  if (!fs.existsSync(configPath)) return undefined;
  try {
    const raw = fs.readFileSync(configPath, 'utf-8');
    const parsed = JSON.parse(raw);
    return parsed as ReskSecurityConfig;
  } catch (e) {
    console.error('[resk-llm] Erreur de chargement config.json:', e);
    return undefined;
  }
} 