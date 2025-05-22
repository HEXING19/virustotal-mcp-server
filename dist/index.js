import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { VirusTotalService } from "./virustotal-service.js";
import { updateApiKey } from "./config.js";
// Initialize VirusTotal service
const virusTotalService = new VirusTotalService();
// Create MCP server
const server = new Server({
    name: "virustotal-api",
    version: "1.0.0"
}, {
    capabilities: {
        functions: {}
    }
});
// Define schemas for all functions
const setApiKeySchema = z.object({
    method: z.literal("mcp_virustotal_set_api_key"),
    params: z.object({
        apiKey: z.string().min(1)
    })
});
const checkApiKeySchema = z.object({
    method: z.literal("mcp_virustotal_check_api_key"),
    params: z.object({})
});
const fileReportSchema = z.object({
    method: z.literal("mcp_virustotal_get_file_report"),
    params: z.object({
        fileHash: z.string().min(1)
    })
});
const urlReportSchema = z.object({
    method: z.literal("mcp_virustotal_get_url_report"),
    params: z.object({
        url: z.string().min(1)
    })
});
const ipReportSchema = z.object({
    method: z.literal("mcp_virustotal_get_ip_report"),
    params: z.object({
        ip: z.string().min(1)
    })
});
const domainReportSchema = z.object({
    method: z.literal("mcp_virustotal_get_domain_report"),
    params: z.object({
        domain: z.string().min(1)
    })
});
// Register function handlers
server.setRequestHandler(setApiKeySchema, async (request) => {
    const { apiKey } = request.params;
    try {
        updateApiKey(apiKey);
        virusTotalService.updateApiKey(apiKey);
        return {
            success: true,
            message: "API key has been set successfully"
        };
    }
    catch (error) {
        return {
            success: false,
            message: `Failed to set API key: ${error.message || 'Unknown error'}`
        };
    }
});
server.setRequestHandler(checkApiKeySchema, async () => {
    try {
        const result = await virusTotalService.checkApiKey();
        return result;
    }
    catch (error) {
        return {
            valid: false,
            message: `Error checking API key: ${error.message || 'Unknown error'}`
        };
    }
});
server.setRequestHandler(fileReportSchema, async (request) => {
    const { fileHash } = request.params;
    return await virusTotalService.getFileReport(fileHash);
});
server.setRequestHandler(urlReportSchema, async (request) => {
    const { url } = request.params;
    return await virusTotalService.getUrlReport(url);
});
server.setRequestHandler(ipReportSchema, async (request) => {
    const { ip } = request.params;
    return await virusTotalService.getIpReport(ip);
});
server.setRequestHandler(domainReportSchema, async (request) => {
    const { domain } = request.params;
    return await virusTotalService.getDomainReport(domain);
});
// Connect to transport
async function main() {
    try {
        console.log("Starting VirusTotal MCP server...");
        const transport = new StdioServerTransport();
        await server.connect(transport);
        console.log("Connected to transport. Server is running.");
    }
    catch (error) {
        console.error("Error starting server:", error);
        process.exit(1);
    }
}
main();
