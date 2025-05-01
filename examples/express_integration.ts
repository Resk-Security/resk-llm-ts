/**
 * Express Integration Example for resk-llm-ts
 * 
 * This example demonstrates how to integrate ReskLLMClient with an Express API
 * to create a secure chatbot endpoint with proper error handling.
 */

import express from 'express';
import bodyParser from 'body-parser';
import { ReskLLMClient, SecurityException } from '../src/index';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
app.use(bodyParser.json());

// Initialize the secure LLM client
const reskClient = new ReskLLMClient({
  openRouterApiKey: process.env.OPENROUTER_API_KEY,
  securityConfig: {
    inputSanitization: { enabled: true },
    piiDetection: { enabled: true, redact: true },
    promptInjection: { enabled: true, level: 'basic' },
    heuristicFilter: { enabled: true },
    canaryTokens: { enabled: true },
    // Add vectorDb if you want more advanced protection
    vectorDb: { 
      enabled: false 
      // To enable, set to true and provide embedding function
    }
  }
});

// Simple API for chat completions
app.post('/api/chat', async (req, res) => {
  try {
    const { message } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    // Get conversation history from session or start a new one
    const conversationHistory = req.body.history || [
      { role: "system", content: "You are a helpful assistant that provides accurate information." }
    ];
    
    // Add the new user message
    conversationHistory.push({ role: "user", content: message });

    // Call the API securely through resk-llm-ts
    const completion = await reskClient.chat.completions.create({
      model: "openai/gpt-4o",
      messages: conversationHistory,
      temperature: 0.7,
      max_tokens: 1000
    });

    // Get the assistant's response
    const assistantResponse = completion.choices[0].message.content;
    
    // Add the assistant response to the history
    conversationHistory.push({ role: "assistant", content: assistantResponse });
    
    // Return the response and updated conversation history
    return res.json({
      response: assistantResponse,
      history: conversationHistory
    });
  } 
  catch (error: any) {
    console.error('Error processing chat request:', error);
    
    // Handle security exceptions specifically
    if (error instanceof SecurityException) {
      return res.status(403).json({ 
        error: 'Security violation detected', 
        details: error.message 
      });
    }
    
    // Handle other API errors
    return res.status(500).json({ 
      error: 'Error processing request',
      details: error.message
    });
  }
});

// Simple static response for root
app.get('/', (req, res) => {
  res.send('Secure LLM API Server - Send POST requests to /api/chat');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Example request:');
  console.log('curl -X POST http://localhost:3000/api/chat \\');
  console.log('  -H "Content-Type: application/json" \\');
  console.log('  -d \'{"message": "Explain API security best practices"}\'\n');
});

/**
 * To run this example:
 * 1. Create a .env file with OPENROUTER_API_KEY or OPENAI_API_KEY and optional PORT
 * 2. Run: npx ts-node examples/express_integration.ts
 * 3. Test using curl or a tool like Postman
 */ 