// @ts-check // Optional: Enable type checking for this config file

import eslint from '@eslint/js'; // Import base eslint rules
import tseslint from 'typescript-eslint'; // Import typescript-eslint tools
import globals from 'globals'; // Import predefined globals

export default tseslint.config(
  // Base recommended rules from ESLint
  eslint.configs.recommended,

  // Rules recommended by typescript-eslint, including parser setup
  ...tseslint.configs.recommended,

  // Configuration specific to project files
  {
    files: ['src/**/*.ts', 'test/**/*.ts'], // Apply these rules only to TS files
    languageOptions: {
      globals: {
        ...globals.node, // Add Node.js globals
        ...globals.jest, // Add Jest globals
      }
    },
    rules: {
      // Custom rules from old config
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['warn', { 'argsIgnorePattern': '^_' }],
    },
  },

  // Ignores (equivalent to ignorePatterns)
  {
    ignores: [
        "node_modules/",
        "dist/",
        // Keep js files like jest.config.js, eslint.config.js out for now
        // "*.js", 
        "*.d.ts"
    ],
  }
); 