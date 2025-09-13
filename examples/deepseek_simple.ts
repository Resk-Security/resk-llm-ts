#!/usr/bin/env bun

/**
 * Simple DeepSeek example for Bun
 * export API_KEY_LLM="your_deepseek_api_key"
 * export PROVIDER=deepseek
 */

import { createProviderConfigFromEnv, PROVIDER_MODELS } from '../src/providers/llm_provider.js';

async function simpleDeepSeekDemo() {
    console.log('🚀 Simple DeepSeek Demo with Bun');
    console.log('═'.repeat(35));

    try {
        // Get provider config from environment
        const config = createProviderConfigFromEnv('deepseek');
        
        console.log('✅ DeepSeek configured');
        console.log(`🔗 Endpoint: ${config.baseUrl}`);
        console.log(`🔑 API Key: ${config.apiKey.slice(0, 8)}...`);
        console.log(`🤖 Models: ${PROVIDER_MODELS.deepseek.join(', ')}\n`);

        // Simple HTTP request to test the connection
        const testRequest = {
            model: 'deepseek-chat',
            messages: [
                {
                    role: 'user',
                    content: 'Say hello in exactly 10 words'
                }
            ],
            max_tokens: 50
        };

        console.log('📡 Making test request to DeepSeek...');
        
        const response = await fetch(`${config.baseUrl}/chat/completions`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${config.apiKey}`,
                'Content-Type': 'application/json',
                ...config.headers
            },
            body: JSON.stringify(testRequest)
        });

        if (response.ok) {
            const data = await response.json();
            console.log('✅ Success! DeepSeek response:');
            console.log(`"${data.choices[0].message.content}"`);
            console.log(`📊 Tokens used: ${data.usage?.total_tokens}`);
        } else {
            const error = await response.text();
            console.log('❌ API Error:', response.status, error);
        }

    } catch (error) {
        console.error('❌ Error:', error.message);
        
        if (error.message.includes('API key not found')) {
            console.log('\n💡 Setup:');
            console.log('   export API_KEY_LLM="your_deepseek_api_key"');
            console.log('   bun run examples/deepseek_simple.ts');
        }
    }

    console.log('\n🎉 Demo completed!');
}

// Run if called directly
if (import.meta.main) {
    simpleDeepSeekDemo();
}

export { simpleDeepSeekDemo };
