import { describe, expect, it } from 'bun:test';
import { handleToolCall, TOOLS } from '../src/tools/index.ts';

describe('MCP Tools Handler Interface', () => {
  it('exposes all required core tools', () => {
    const names = TOOLS.map(t => t.name);
    expect(names).toContain('scan_email_payload');
    expect(names).toContain('verify_url_reputation');
    expect(names).toContain('inspect_attachments');
  });

  it('executes scan_email_payload tool correctly', async () => {
    const response = await handleToolCall('scan_email_payload', {
      body: "Hello world, check https://spotify.com",
      headers: {
        from: "user@spotify.com",
        spf: "pass",
        dmarc: "pass"
      }
    });

    expect(response.isError).toBeUndefined();
    expect(response.content.length).toBeGreaterThan(0);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.securityScore).toBeGreaterThanOrEqual(90);
    expect(parsed.threatLevel).toBe("SAFE");
  });

  it('executes verify_url_reputation tool correctly', async () => {
    const response = await handleToolCall('verify_url_reputation', {
      urls: ["https://g0ogle.com/login", "https://google.com"]
    });

    expect(response.isError).toBeUndefined();
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.summary.totalUrls).toBe(2);
    expect(parsed.results.some((r: any) => r.typosquattedBrand === "google")).toBe(true);
  });

  it('executes inspect_attachments tool correctly', async () => {
    const response = await handleToolCall('inspect_attachments', {
      attachments: [
        {
          filename: "document.pdf",
          data: Buffer.from("%PDF-1.4").toString('base64')
        }
      ]
    });

    expect(response.isError).toBeUndefined();
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.summary.totalAttachments).toBe(1);
    expect(parsed.results[0].magicByteMatch).toBe(true);
  });

  it('returns error result for unknown tool name', async () => {
    const response = await handleToolCall('unknown_tool', {});
    expect(response.isError).toBe(true);
  });
});
