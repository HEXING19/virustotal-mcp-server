import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// Get the directory name of the current module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Paths
const configDir = path.resolve(__dirname, '../config');
const envPath = path.join(configDir, '.env');

// Load environment variables
dotenv.config({ path: envPath });

export interface Config {
  apiKey: string;
}

export function getConfig(): Config {
  return {
    apiKey: process.env.VIRUSTOTAL_API_KEY || '',
  };
}

export function updateApiKey(apiKey: string): void {
  try {
    // Ensure config directory exists
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    
    // Write the new API key to the .env file
    fs.writeFileSync(envPath, `VIRUSTOTAL_API_KEY=${apiKey}`);
    
    // Update the environment variable in the current process
    process.env.VIRUSTOTAL_API_KEY = apiKey;
    
    console.log('API key updated successfully.');
  } catch (error) {
    console.error('Failed to update API key:', error);
    throw new Error('Failed to update API key');
  }
} 