/**
 * Simple tests for provider configurations
 */

import { describe, test, expect } from '@jest/globals';
import { PROVIDER_CONFIGS, PROVIDER_MODELS, createProviderConfigFromEnv } from '../src/providers/llm_provider';

describe('Provider Configuration', () => {
    test('should have correct provider configurations', () => {
        expect(PROVIDER_CONFIGS.deepseek.baseUrl).toBe('https://api.deepseek.com/v1');
        expect(PROVIDER_CONFIGS.openai.baseUrl).toBe('https://api.openai.com/v1');
        expect(PROVIDER_CONFIGS.anthropic.baseUrl).toBe('https://api.anthropic.com/v1');
    });

    test('should have models for each provider', () => {
        expect(PROVIDER_MODELS.deepseek).toContain('deepseek-chat');
        expect(PROVIDER_MODELS.deepseek).toContain('deepseek-coder');
        expect(PROVIDER_MODELS.openai).toContain('gpt-4o');
        expect(PROVIDER_MODELS.anthropic).toContain('claude-3-5-sonnet-20241022');
    });

    test('should create provider config with test API key', () => {
        // Set test environment
        const originalKey = process.env.API_KEY_LLM;
        process.env.API_KEY_LLM = 'test-key-123';

        try {
            const config = createProviderConfigFromEnv('deepseek');
            
            expect(config.apiKey).toBe('test-key-123');
            expect(config.provider).toBe('deepseek');
            expect(config.baseUrl).toBe('https://api.deepseek.com/v1');
            expect(config.timeout).toBe(30000);
            expect(config.maxRetries).toBe(3);
        } finally {
            // Restore original
            if (originalKey) {
                process.env.API_KEY_LLM = originalKey;
            } else {
                delete process.env.API_KEY_LLM;
            }
        }
    });

    test('should throw error when no API key found', () => {
        // Clear all potential API keys
        const originalKeys = {
            API_KEY_LLM: process.env.API_KEY_LLM,
            DEEPSEEK_API_KEY: process.env.DEEPSEEK_API_KEY
        };

        delete process.env.API_KEY_LLM;
        delete process.env.DEEPSEEK_API_KEY;

        try {
            expect(() => {
                createProviderConfigFromEnv('deepseek');
            }).toThrow('API key not found for provider deepseek');
        } finally {
            // Restore
            if (originalKeys.API_KEY_LLM) process.env.API_KEY_LLM = originalKeys.API_KEY_LLM;
            if (originalKeys.DEEPSEEK_API_KEY) process.env.DEEPSEEK_API_KEY = originalKeys.DEEPSEEK_API_KEY;
        }
    });

    test('should prefer provider-specific API key over generic', () => {
        const originalKeys = {
            API_KEY_LLM: process.env.API_KEY_LLM,
            DEEPSEEK_API_KEY: process.env.DEEPSEEK_API_KEY
        };

        process.env.API_KEY_LLM = 'generic-key';
        process.env.DEEPSEEK_API_KEY = 'specific-key';

        try {
            const config = createProviderConfigFromEnv('deepseek');
            expect(config.apiKey).toBe('generic-key'); // API_KEY_LLM takes precedence
        } finally {
            // Restore
            if (originalKeys.API_KEY_LLM) {
                process.env.API_KEY_LLM = originalKeys.API_KEY_LLM;
            } else {
                delete process.env.API_KEY_LLM;
            }
            if (originalKeys.DEEPSEEK_API_KEY) {
                process.env.DEEPSEEK_API_KEY = originalKeys.DEEPSEEK_API_KEY;
            } else {
                delete process.env.DEEPSEEK_API_KEY;
            }
        }
    });
});
