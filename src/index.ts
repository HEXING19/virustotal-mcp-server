import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { 
  CallToolRequestSchema,
  ListToolsRequestSchema 
} from "@modelcontextprotocol/sdk/types.js";
import { VirusTotalService } from "./virustotal-service.ts";
import { updateApiKey } from "./config.ts";

// Initialize VirusTotal service
const virusTotalService = new VirusTotalService();

// Create MCP server
const server = new Server(
  {
    name: "virustotal-api",
    version: "1.0.0"
  },
  {
    capabilities: {
      tools: {
        mcp_virustotal_set_api_key: {
          description: "Set your VirusTotal API key",
          parameters: {
            type: "object",
            properties: {
              apiKey: { type: "string", description: "Your VirusTotal API key" }
            },
            required: ["apiKey"]
          }
        },
        mcp_virustotal_check_api_key: {
          description: "Check if your VirusTotal API key is valid",
          parameters: {
            type: "object",
            properties: {}
          }
        },
        mcp_virustotal_get_file_report: {
          description: "Get a report for a file hash from VirusTotal",
          parameters: {
            type: "object",
            properties: {
              fileHash: { type: "string", description: "The hash of the file to check" }
            },
            required: ["fileHash"]
          }
        },
        mcp_virustotal_get_url_report: {
          description: "Get a report for a URL from VirusTotal",
          parameters: {
            type: "object",
            properties: {
              url: { type: "string", description: "The URL to check" }
            },
            required: ["url"]
          }
        },
        mcp_virustotal_get_ip_report: {
          description: "Get a report for an IP address from VirusTotal",
          parameters: {
            type: "object",
            properties: {
              ip: { type: "string", description: "The IP address to check" }
            },
            required: ["ip"]
          }
        },
        mcp_virustotal_get_domain_report: {
          description: "Get a report for a domain from VirusTotal",
          parameters: {
            type: "object",
            properties: {
              domain: { type: "string", description: "The domain to check" }
            },
            required: ["domain"]
          }
        }
      }
    }
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "mcp_virustotal_set_api_key",
        description: "Set your VirusTotal API key",
        inputSchema: {
          type: "object",
          properties: {
            apiKey: { type: "string", description: "Your VirusTotal API key" }
          },
          required: ["apiKey"]
        }
      },
      {
        name: "mcp_virustotal_check_api_key",
        description: "Check if your VirusTotal API key is valid",
        inputSchema: {
          type: "object",
          properties: {}
        }
      },
      {
        name: "mcp_virustotal_get_file_report",
        description: "Get a report for a file hash from VirusTotal",
        inputSchema: {
          type: "object",
          properties: {
            fileHash: { type: "string", description: "The hash of the file to check" }
          },
          required: ["fileHash"]
        }
      },
      {
        name: "mcp_virustotal_get_url_report",
        description: "Get a report for a URL from VirusTotal",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", description: "The URL to check" }
          },
          required: ["url"]
        }
      },
      {
        name: "mcp_virustotal_get_ip_report",
        description: "Get a report for an IP address from VirusTotal",
        inputSchema: {
          type: "object",
          properties: {
            ip: { type: "string", description: "The IP address to check" }
          },
          required: ["ip"]
        }
      },
      {
        name: "mcp_virustotal_get_domain_report",
        description: "Get a report for a domain from VirusTotal",
        inputSchema: {
          type: "object",
          properties: {
            domain: { type: "string", description: "The domain to check" }
          },
          required: ["domain"]
        }
      }
    ]
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "mcp_virustotal_set_api_key":
      try {
        const { apiKey } = args as { apiKey: string };
        updateApiKey(apiKey);
        virusTotalService.updateApiKey(apiKey);
        return { 
          content: [{ 
            type: "text",
            text: "API key has been set successfully"
          }]
        };
      } catch (error: any) {
        return { 
          content: [{ 
            type: "text",
            text: `Failed to set API key: ${error.message || 'Unknown error'}`
          }],
          isError: true
        };
      }

    case "mcp_virustotal_check_api_key":
      try {
        const result = await virusTotalService.checkApiKey();
        return {
          content: [{
            type: "text",
            text: JSON.stringify(result)
          }]
        };
      } catch (error: any) {
        return { 
          content: [{ 
            type: "text",
            text: `Error checking API key: ${error.message || 'Unknown error'}`
          }],
          isError: true
        };
      }

    case "mcp_virustotal_get_file_report":
      const { fileHash } = args as { fileHash: string };
      const fileReport = await virusTotalService.getFileReport(fileHash);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(fileReport)
        }]
      };

    case "mcp_virustotal_get_url_report":
      const { url } = args as { url: string };
      const urlReport = await virusTotalService.getUrlReport(url);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(urlReport)
        }]
      };

    case "mcp_virustotal_get_ip_report":
      const { ip } = args as { ip: string };
      const ipReport = await virusTotalService.getIpReport(ip);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(ipReport)
        }]
      };

    case "mcp_virustotal_get_domain_report":
      const { domain } = args as { domain: string };
      const domainReport = await virusTotalService.getDomainReport(domain);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(domainReport)
        }]
      };

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

// Connect to transport
async function main() {
  try {
    console.log("Starting VirusTotal MCP server...");
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.log("Connected to transport. Server is running.");
  } catch (error) {
    console.error("Error starting server:", error);
    process.exit(1);
  }
}

main();