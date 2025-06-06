import axios from 'axios';
import { getConfig } from './config.js';
const BASE_URL = 'https://www.virustotal.com/api/v3';
export class VirusTotalService {
    constructor() {
        this.apiKey = getConfig().apiKey;
    }
    /**
     * Updates the API key used for VirusTotal API requests
     */
    updateApiKey(apiKey) {
        this.apiKey = apiKey;
    }
    /**
     * Get the current API key status (valid or invalid)
     */
    async checkApiKey() {
        if (!this.apiKey) {
            return { valid: false, message: 'API key is not set' };
        }
        try {
            // Attempt to make a simple API request to verify the key
            const response = await axios.get(`${BASE_URL}/ip_addresses/1.1.1.1`, {
                headers: {
                    'x-apikey': this.apiKey
                }
            });
            return { valid: true, message: 'API key is valid' };
        }
        catch (error) {
            if (error.response && error.response.status === 401) {
                return { valid: false, message: 'Invalid API key' };
            }
            else {
                return {
                    valid: false,
                    message: `Error validating API key: ${error.message || 'Unknown error'}`
                };
            }
        }
    }
    /**
     * Get information about a file by its hash
     */
    async getFileReport(fileHash) {
        try {
            const response = await axios.get(`${BASE_URL}/files/${fileHash}`, {
                headers: {
                    'x-apikey': this.apiKey
                }
            });
            return { success: true, data: response.data };
        }
        catch (error) {
            return {
                success: false,
                error: error.response?.data?.error || error.message || 'Unknown error'
            };
        }
    }
    /**
     * Get information about a URL
     */
    async getUrlReport(url) {
        try {
            // URL needs to be encoded for API request
            const encodedUrl = encodeURIComponent(url);
            const response = await axios.get(`${BASE_URL}/urls/${encodedUrl}`, {
                headers: {
                    'x-apikey': this.apiKey
                }
            });
            return { success: true, data: response.data };
        }
        catch (error) {
            return {
                success: false,
                error: error.response?.data?.error || error.message || 'Unknown error'
            };
        }
    }
    /**
     * Get information about an IP address
     */
    async getIpReport(ip) {
        try {
            const response = await axios.get(`${BASE_URL}/ip_addresses/${ip}`, {
                headers: {
                    'x-apikey': this.apiKey
                }
            });
            return { success: true, data: response.data };
        }
        catch (error) {
            return {
                success: false,
                error: error.response?.data?.error || error.message || 'Unknown error'
            };
        }
    }
    /**
     * Get information about a domain
     */
    async getDomainReport(domain) {
        try {
            const response = await axios.get(`${BASE_URL}/domains/${domain}`, {
                headers: {
                    'x-apikey': this.apiKey
                }
            });
            return { success: true, data: response.data };
        }
        catch (error) {
            return {
                success: false,
                error: error.response?.data?.error || error.message || 'Unknown error'
            };
        }
    }
}
