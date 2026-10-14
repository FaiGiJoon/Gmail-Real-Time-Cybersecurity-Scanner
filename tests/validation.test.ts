import { describe, expect, it } from 'bun:test';
import {
  scanEmailPayloadSchema,
  verifyUrlReputationSchema,
  inspectAttachmentsSchema
} from '../src/schemas/index.ts';

describe('Zod Validation Schemas', () => {
  it('validates scanEmailPayloadSchema successfully', () => {
    const validPayload = {
      body: "Hello, please review this document.",
      headers: {
        from: "support@spotify.com",
        spf: "pass",
        dkim: "pass",
        dmarc: "pass"
      },
      attachments: [
        { filename: "document.pdf", size: 1024 }
      ]
    };

    const parsed = scanEmailPayloadSchema.safeParse(validPayload);
    expect(parsed.success).toBe(true);
  });

  it('validates verifyUrlReputationSchema successfully', () => {
    const validSingle = { urls: "https://spotify.com" };
    expect(verifyUrlReputationSchema.safeParse(validSingle).success).toBe(true);

    const validArray = { urls: ["https://spotify.com", "https://google.com"], context: "Visit links" };
    expect(verifyUrlReputationSchema.safeParse(validArray).success).toBe(true);
  });

  it('rejects invalid inspectAttachmentsSchema with empty array', () => {
    const invalidInput = { attachments: [] };
    const parsed = inspectAttachmentsSchema.safeParse(invalidInput);
    expect(parsed.success).toBe(false);
  });
});
