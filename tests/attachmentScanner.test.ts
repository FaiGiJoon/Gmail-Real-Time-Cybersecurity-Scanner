import { describe, expect, it } from 'bun:test';
import {
  computeHashes,
  checkDoubleExtension,
  verifyMagicBytes,
  scanPdfStructure,
  inspectAttachments
} from '../src/scanner/attachmentScanner.ts';

describe('Attachment Scanner', () => {
  it('computes SHA-256 and MD5 hashes correctly', async () => {
    const hashes = await computeHashes("Hello World");
    expect(hashes.sha256).toBe("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");
    expect(hashes.md5).toBe("b10a8db164e0754105b7a99be72e3fe5");
  });

  it('detects double extension executables', () => {
    const res1 = checkDoubleExtension("invoice.pdf.exe");
    expect(res1.hasDoubleExt).toBe(true);
    expect(res1.ext2).toBe(".exe");

    const res2 = checkDoubleExtension("report.final.docx");
    expect(res2.hasDoubleExt).toBe(false);
  });

  it('verifies magic bytes for files', () => {
    // PDF Magic Bytes: %PDF -> [0x25, 0x50, 0x44, 0x46]
    const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x00, 0x00]);
    const pdfMatch = verifyMagicBytes("doc.pdf", pdfBytes);
    expect(pdfMatch.match).toBe(true);
    expect(pdfMatch.detectedType).toBe("PDF");

    // Mismatch check: Filename .pdf but bytes are PNG [0x89, 0x50, 0x4E, 0x47]
    const pngBytes = new Uint8Array([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    const mismatch = verifyMagicBytes("doc.pdf", pngBytes);
    expect(mismatch.match).toBe(false);
    expect(mismatch.detectedType).toBe("PNG");
  });

  it('scans PDF structure for embedded JavaScript and actions', () => {
    const maliciousPdfContent = "%PDF-1.4\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('PWNED');) >>\nendobj";
    const traits = scanPdfStructure(maliciousPdfContent);
    expect(traits.some(t => t.includes("JavaScript"))).toBe(true);
  });

  it('inspects attachments array completely', async () => {
    const result = await inspectAttachments([
      {
        filename: "invoice.pdf.exe",
        data: Buffer.from("%PDF-1.4").toString('base64'),
        size: 100
      }
    ]);

    expect(result.summary.totalAttachments).toBe(1);
    expect(result.summary.maliciousCount).toBe(1);
    expect(result.results[0].hasDoubleExtension).toBe(true);
    expect(result.results[0].threatLevel).toBe("MALICIOUS");
  });
});
