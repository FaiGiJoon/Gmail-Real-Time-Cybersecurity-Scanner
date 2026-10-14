import { z } from 'zod';

export const emailHeaderSchema = z.object({
  from: z.string().optional(),
  to: z.string().optional(),
  subject: z.string().optional(),
  spf: z.enum(['pass', 'fail', 'softfail', 'neutral', 'none', 'unknown']).or(z.string()).optional(),
  dkim: z.enum(['pass', 'fail', 'none', 'unknown']).or(z.string()).optional(),
  dmarc: z.enum(['pass', 'fail', 'none', 'unknown']).or(z.string()).optional(),
  received: z.array(z.string()).or(z.string()).optional(),
  replyTo: z.string().optional(),
  returnPath: z.string().optional(),
}).passthrough();

export const attachmentInputSchema = z.object({
  filename: z.string(),
  contentType: z.string().optional(),
  size: z.number().nonnegative().optional(),
  data: z.string().optional(), // Base64 or plain string content
  hash: z.string().optional(), // Precomputed SHA-256 or MD5 hash
});

export const scanEmailPayloadSchema = z.object({
  rawEmail: z.string().optional(),
  body: z.string().optional(),
  headers: z.union([emailHeaderSchema, z.record(z.unknown())]).optional(),
  attachmentHashes: z.array(z.string()).optional(),
  attachments: z.array(attachmentInputSchema).optional(),
  sender: z.string().optional(),
});

export const verifyUrlReputationSchema = z.object({
  urls: z.union([z.string(), z.array(z.string())]),
  context: z.string().optional(),
});

export const inspectAttachmentsSchema = z.object({
  attachments: z.array(attachmentInputSchema).min(1, "At least one attachment must be provided"),
});

export const configSchema = z.object({
  SAFE_BROWSING_API_KEY: z.string().optional(),
  VIRUSTOTAL_API_KEY: z.string().optional(),
  CLOUD_VISION_API_KEY: z.string().optional(),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  NODE_ENV: z.string().default('development'),
  INTERNAL_DOMAIN: z.string().default('spotify.com'),
  VIP_NAMES: z.string().default('Daniel Ek,Martin Lorentzon,Paul Vogel'),
});

export type EmailHeader = z.infer<typeof emailHeaderSchema>;
export type AttachmentInput = z.infer<typeof attachmentInputSchema>;
export type ScanEmailPayload = z.infer<typeof scanEmailPayloadSchema>;
export type VerifyUrlReputationInput = z.infer<typeof verifyUrlReputationSchema>;
export type InspectAttachmentsInput = z.infer<typeof inspectAttachmentsSchema>;
export type Config = z.infer<typeof configSchema>;
