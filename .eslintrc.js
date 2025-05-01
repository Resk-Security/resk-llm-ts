module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: [
    '@typescript-eslint',
  ],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended', // Règles recommandées pour TypeScript
  ],
  env: {
    node: true, // Pour reconnaître les variables globales Node.js
    jest: true, // Pour reconnaître les variables globales Jest
  },
  rules: {
    // Ajoute ou modifie des règles ici si nécessaire
    // Exemple : '@typescript-eslint/no-unused-vars': 'warn',
     '@typescript-eslint/no-explicit-any': 'warn', // Peut être utile au début
     '@typescript-eslint/no-unused-vars': ['warn', { 'argsIgnorePattern': '^_' }], // Avertir sur les vars inutilisées sauf si préfixées par _
  },
  ignorePatterns: ["node_modules/", "dist/", "*.js", "*.d.ts"], // Ignore les JS/d.ts générés et node_modules
}; 