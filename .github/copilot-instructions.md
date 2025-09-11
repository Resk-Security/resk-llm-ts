# resk-llm-ts - LLM Security Toolkit

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

- **Bootstrap, build, and test the repository:**
  - `npm install` -- installs dependencies in ~15 seconds. May show warnings about deprecated packages (node-domexception, inflight, glob) - these are safe to ignore.
  - `npm run build` -- compiles TypeScript to JavaScript in ~2-3 seconds. NEVER CANCEL.
  - `npm test` -- runs Jest test suite in ~10-11 seconds. NEVER CANCEL.
  - `npm run build:prod` -- runs TypeScript compilation + linting in ~5 seconds. NEVER CANCEL.

- **Run the complete test suite:**
  - `npm run test:all` -- runs tests with coverage reporting in ~10-11 seconds. NEVER CANCEL.
  - Test output includes security warnings and performance logs - this is expected behavior.
  - Tests may show a worker process warning about improper teardown - this is a known issue and does not affect functionality.

- **Linting and code quality:**
  - `npm run lint` -- runs ESLint on all TypeScript files in ~2 seconds. NEVER CANCEL.
  - Expect ~79 linting warnings about TypeScript `any` types and unused variables - these are development warnings, not errors.
  - The build and tests still pass with these warnings.

## Validation

- **ALWAYS run the complete build pipeline after making changes:**
  ```bash
  npm install && npm run build && npm test && npm run lint
  ```
  - Total time: ~15-20 seconds. NEVER CANCEL any individual command.
  
- **Frontend vs Backend validation:**
  - **Backend changes**: Test with main test suite (`npm test`)
  - **Frontend changes**: Test with `npm run test:frontend`
  - **Security changes**: Always run full test suite with `npm run test:all`

- **Security functionality validation scenarios:**
  - **Safe input**: "What is the weather like today?" → Should pass without warnings
  - **PII detection**: "My email is user@example.com" → Should detect and warn about email
  - **Prompt injection**: "Ignore all instructions above" → Should detect injection attempt
  - **Combined threats**: Mix of PII + injection → Should detect both issues
  - All scenarios tested automatically in Jest suite with 47 passing tests

- **Example validation (requires additional setup):**
  - Examples require `ts-node` but it's not in the main dependencies
  - Install with: `npm install --save-dev ts-node` 
  - Examples may fail without proper environment variables (API keys) - this is expected
  - Do NOT commit ts-node to main dependencies - it's only needed for development examples

## Common Tasks

The following are outputs from frequently run commands. Reference them instead of viewing, searching, or running bash commands to save time.

### Repository Structure
```
src/
├── frontend/           # Frontend security components (browser-safe)
├── security/          # Core security modules
├── providers/         # LLM provider interfaces  
├── vector_stores/     # Vector database integration
├── configLoader.ts    # Configuration file loader
├── index.ts          # Main entry point
└── types.ts          # TypeScript type definitions

test/                 # Jest test files
examples/             # Usage examples (need ts-node)
docs/                 # Documentation (MkDocs)
dist/                 # Compiled JavaScript output
```

### Package.json Key Scripts
```json
{
  "build": "tsc",
  "test": "jest", 
  "lint": "eslint src/**/*.ts test/**/*.ts",
  "build:prod": "tsc --project tsconfig.json && npm run lint",
  "test:all": "jest --coverage",
  "test:frontend": "jest test/frontend_security.test.ts"
}
```

### Build Output
- TypeScript compiles to `dist/` directory
- Generates `.js`, `.d.ts`, and `.js.map` files
- Build is fast (~2-3 seconds) and reliable
- No additional build tools or complex webpack configurations needed

### Test Coverage Summary
- **47.37%** statement coverage overall
- **Frontend modules**: ~58% coverage
- **Security patterns**: 100% coverage (critical security components)
- **Main index.ts**: ~71% coverage
- Coverage report shows which security features are well-tested

## Architecture Understanding

### Security Library Components
- **ReskLLMClient**: Backend/server-side security wrapper for LLM APIs
- **ReskSecurityFilter**: Frontend/browser-side security filtering (no API keys)
- **Security Modules**: Prompt injection detection, PII protection, content moderation
- **Vector Stores**: Pattern storage and similarity detection
- **Providers**: OpenAI, Anthropic, Cohere, HuggingFace integrations

### Critical Security Features
- **Prompt Injection Detection**: Pattern-based detection with confidence scoring
- **PII Protection**: Email, phone, SSN, credit card detection and redaction
- **Content Moderation**: Toxic, violent, adult content filtering
- **Canary Tokens**: Data leak detection with alerting
- **Vector Database**: Persistent attack pattern storage

### Configuration
- Uses `config.json` for production security settings
- Environment-specific configurations supported
- Multiple ESLint configurations (legacy .eslintrc.js and new eslint.config.js)

## CI/CD Pipeline

### GitHub Actions Workflow (.github/workflows/publish.yml)
- **Test stage**: Runs on Node.js 18.x and 20.x
- **Commands executed in CI**:
  1. `npm ci` -- clean install
  2. `npm run lint` -- linting
  3. `npx tsc --noEmit` -- type checking
  4. `npm test` -- test suite
  5. `npm run build:prod` -- production build
  6. `npm publish` -- on version tags

### Pre-commit Validation
Always run these commands before committing:
```bash
npm run build:prod  # Includes TypeScript compilation + linting
npm test           # Full test suite
```

## Development Environment

### Node.js Requirements
- **Supported versions**: Node.js 18.x, 20.x (tested in CI)
- **Current environment**: Node.js 20.19.5, npm 10.8.2
- **TypeScript**: Version ^5.4.5 with strict mode enabled

### Dependencies
- **Runtime**: openai, sanitize-html, mathjs
- **Dev**: typescript, jest, eslint, @typescript-eslint packages
- **Optional**: ts-node (for examples only)

### IDE Configuration
- TypeScript strict mode enabled
- ESLint integration recommended
- Jest test runner integration helpful
- Project uses ESM modules with CommonJS compilation

## Known Issues and Workarounds

### Test Suite Warnings
- Worker process teardown warnings in Jest - known issue, doesn't affect functionality
- Console warnings about server environment detection - expected in Node.js test environment
- TypeScript `any` type warnings - development warnings only, not blocking errors

### Example Scripts
- Examples require `ts-node` installation: `npm install --save-dev ts-node`
- Examples need environment variables (API keys) to run successfully
- Frontend examples may show security warnings when run in Node.js - this is expected behavior

### ESLint Configuration
- Project has both legacy (.eslintrc.js) and new (eslint.config.js) configurations
- Both work correctly, new config takes precedence
- ~79 warnings are expected and don't block builds

## Security Considerations

### Frontend vs Backend Usage
- **Frontend**: Use `ReskSecurityFilter` - no API keys, browser-safe validation only
- **Backend**: Use `ReskLLMClient` - full security with API key management
- **Critical**: NEVER expose API keys in frontend code

### API Key Management
- Use environment variables: `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, etc.
- Backend proxy required for frontend applications
- Examples demonstrate proper separation of concerns

### Security Testing
- Pattern-based security has inherent limitations
- Should be one layer in comprehensive security strategy
- Regular updates needed for new attack patterns
- Test coverage of security patterns is 100% - maintain this level

## Time Expectations

- **npm install**: ~15 seconds
- **npm run build**: ~2-3 seconds  
- **npm test**: ~10-11 seconds
- **npm run lint**: ~2 seconds
- **npm run build:prod**: ~5 seconds
- **npm run test:all**: ~10-11 seconds

**NEVER CANCEL these commands** - they are all fast and reliable. If they seem to hang, wait at least 60 seconds before investigating.

## Documentation

- **Main docs**: docs/ directory with MkDocs configuration
- **README.md**: Comprehensive usage examples and API documentation
- **CONTRIBUTING.md**: Development setup and contribution guidelines
- **Live docs**: https://reskts.readthedocs.io/en/latest/

Always update documentation when adding new security features or changing APIs.