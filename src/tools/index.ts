import {
  scanEmailPayloadSchema,
  verifyUrlReputationSchema,
  inspectAttachmentsSchema,
  type ScanEmailPayload,
  type VerifyUrlReputationInput,
  type InspectAttachmentsInput
} from '../schemas/index.ts';
import { scanEmailPayload } from '../scanner/emailScanner.ts';
import { verifyUrlReputation } from '../scanner/urlScanner.ts';
import { inspectAttachments } from '../scanner/attachmentScanner.ts';
import { config } from '../utils/config.ts';
import { logger } from '../utils/logger.ts';

export const TOOLS = [
  {
    name: 'scan_email_payload',
    description: 'Ingests raw email data, headers, body content, and attachments for deep threat inspection, header auditing, linguistic drift detection, prompt injection defense, and non-linear threat scoring.',
    inputSchema: {
      type: 'object',
      properties: {
        rawEmail: { type: 'string', description: 'Raw RFC822 email payload text' },
        body: { type: 'string', description: 'Extracted email body content (HTML or plain text)' },
        headers: {
          type: 'object',
          description: 'Email headers object including from, to, subject, spf, dkim, dmarc, received'
        },
        attachmentHashes: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of precomputed attachment hashes'
        },
        attachments: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              filename: { type: 'string' },
              contentType: { type: 'string' },
              size: { type: 'number' },
              data: { type: 'string', description: 'Base64 or raw string attachment content' },
              hash: { type: 'string' }
            },
            required: ['filename']
          },
          description: 'List of attachment objects'
        },
        sender: { type: 'string', description: 'Sender email address or Display Name' }
      }
    }
  },
  {
    name: 'verify_url_reputation',
    description: 'Evaluates extracted hyperlinks against heuristic risk factors, homograph Punycode attacks, typosquatting brands, link-anchor mismatches, and threat intelligence feeds.',
    inputSchema: {
      type: 'object',
      properties: {
        urls: {
          oneOf: [
            { type: 'string' },
            { type: 'array', items: { type: 'string' } }
          ],
          description: 'Single URL string or array of URLs to evaluate'
        },
        context: { type: 'string', description: 'Surrounding anchor text or email body context' }
      },
      required: ['urls']
    }
  },
  {
    name: 'inspect_attachments',
    description: 'Computes cryptographic SHA-256 and MD5 file hashes, verifies binary magic bytes, detects double extension spoofs, scans PDF structures, and checks VirusTotal feeds.',
    inputSchema: {
      type: 'object',
      properties: {
        attachments: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              filename: { type: 'string' },
              contentType: { type: 'string' },
              size: { type: 'number' },
              data: { type: 'string', description: 'Base64 or string attachment content' },
              hash: { type: 'string' }
            },
            required: ['filename']
          },
          description: 'List of attachment objects to inspect'
        }
      },
      required: ['attachments']
    }
  }
];

export async function handleToolCall(name: string, args: unknown): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  try {
    logger.info(`MCP Tool Call received: ${name}`);

    if (name === 'scan_email_payload') {
      const parsed = scanEmailPayloadSchema.parse(args);
      const result = await scanEmailPayload(
        parsed as ScanEmailPayload,
        {
          safeBrowsingKey: config.SAFE_BROWSING_API_KEY,
          virusTotalKey: config.VIRUSTOTAL_API_KEY
        },
        {
          internalDomain: config.INTERNAL_DOMAIN,
          vipNames: config.VIP_NAMES.split(',')
        }
      );
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    }

    if (name === 'verify_url_reputation') {
      const parsed = verifyUrlReputationSchema.parse(args);
      const result = await verifyUrlReputation(
        parsed.urls,
        parsed.context,
        config.SAFE_BROWSING_API_KEY
      );
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    }

    if (name === 'inspect_attachments') {
      const parsed = inspectAttachmentsSchema.parse(args);
      const result = await inspectAttachments(
        parsed.attachments,
        config.VIRUSTOTAL_API_KEY
      );
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    }

    return {
      content: [{ type: 'text', text: `Unknown tool name: ${name}` }],
      isError: true
    };
  } catch (error: any) {
    logger.error(`Error executing MCP tool ${name}:`, error);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            error: error.message || 'Tool execution failed',
            details: error.errors || undefined
          }, null, 2)
        }
      ],
      isError: true
    };
  }
}
