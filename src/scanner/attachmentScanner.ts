import { crypto } from 'bun';
import { SCANNER_CONSTANTS } from './constants.ts';
import { logger } from '../utils/logger.ts';
import type { AttachmentInput } from '../schemas/index.ts';

export interface AttachmentAuditResult {
  filename: string;
  contentType?: string;
  size?: number;
  sha256: string;
  md5: string;
  magicByteMatch: boolean;
  detectedType: string | null;
  hasDoubleExtension: boolean;
  hasExecutableExtension: boolean;
  suspiciousTraits: string[];
  threatLevel: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS';
  virusTotalHits?: number;
}

/**
 * Computes SHA-256 and MD5 hashes for string or Uint8Array data.
 */
export async function computeHashes(data: Uint8Array | string, isBase64 = false): Promise<{ sha256: string; md5: string }> {
  let bytes: Uint8Array;
  if (typeof data === 'string') {
    if (isBase64) {
      try {
        bytes = Buffer.from(data, 'base64');
      } catch {
        bytes = new TextEncoder().encode(data);
      }
    } else {
      bytes = new TextEncoder().encode(data);
    }
  } else {
    bytes = data;
  }

  const sha256Hasher = new Bun.CryptoHasher("sha256");
  sha256Hasher.update(bytes);
  const sha256 = sha256Hasher.digest("hex");

  const md5Hasher = new Bun.CryptoHasher("md5");
  md5Hasher.update(bytes);
  const md5 = md5Hasher.digest("hex");

  return { sha256, md5 };
}

/**
 * Checks for double extensions like "invoice.pdf.exe" or "doc.docx.js".
 */
export function checkDoubleExtension(filename: string): { hasDoubleExt: boolean; ext1?: string; ext2?: string } {
  const parts = filename.split('.');
  if (parts.length >= 3) {
    const ext2 = '.' + parts[parts.length - 1].toLowerCase();
    const ext1 = '.' + parts[parts.length - 2].toLowerCase();
    const isExec = SCANNER_CONSTANTS.EXECUTABLE_EXTENSIONS.includes(ext2);
    if (isExec) {
      return { hasDoubleExt: true, ext1, ext2 };
    }
  }
  return { hasDoubleExt: false };
}

/**
 * Verifies magic bytes signature of binary data against expected file extension.
 */
export function verifyMagicBytes(filename: string, bytes: Uint8Array): { match: boolean; detectedType: string | null } {
  if (bytes.length < 4) return { match: true, detectedType: null };

  const ext = filename.split('.').pop()?.toUpperCase();
  if (!ext) return { match: true, detectedType: null };

  let detectedType: string | null = null;
  for (const [type, signature] of Object.entries(SCANNER_CONSTANTS.MAGIC_BYTES)) {
    let match = true;
    for (let i = 0; i < signature.length; i++) {
      if (bytes[i] !== signature[i]) {
        match = false;
        break;
      }
    }
    if (match) {
      detectedType = type;
      break;
    }
  }

  if (!detectedType) {
    return { match: true, detectedType: null };
  }

  // Handle zip-based extensions (DOCX, XLSX, etc.)
  if (['DOCX', 'XLSX', 'ZIP'].includes(ext) && detectedType === 'ZIP') {
    return { match: true, detectedType: ext };
  }

  const match = ext === detectedType;
  return { match, detectedType };
}

/**
 * Scans PDF binary structure or text for suspicious PDF elements.
 */
export function scanPdfStructure(data: Uint8Array | string): string[] {
  const traits: string[] = [];
  const text = typeof data === 'string'
    ? (data.includes('%PDF') ? data : Buffer.from(data, 'base64').toString('latin1'))
    : new TextDecoder('latin1').decode(data);

  if (!text.startsWith('%PDF')) return traits;

  if (/\/JavaScript|\/JS\b/i.test(text)) {
    traits.push("PDF contains embedded JavaScript (/JavaScript or /JS)");
  }
  if (/\/Launch\b/i.test(text)) {
    traits.push("PDF contains launch action (/Launch) executing external commands");
  }
  if (/\/EmbeddedFile\b/i.test(text)) {
    traits.push("PDF contains embedded file objects (/EmbeddedFile)");
  }
  if (/\/OpenAction|\/AA\b/i.test(text)) {
    traits.push("PDF contains auto-execution triggers (/OpenAction)");
  }

  return traits;
}

/**
 * Checks VirusTotal API for file hash if key is present.
 */
async function checkVirusTotal(hash: string, apiKey?: string): Promise<number | undefined> {
  if (!apiKey) return undefined;
  try {
    const url = `${SCANNER_CONSTANTS.VIRUSTOTAL_ENDPOINT}${hash}`;
    const response = await fetch(url, {
      headers: { 'x-apikey': apiKey }
    });
    if (response.ok) {
      const data = await response.json() as any;
      const stats = data.data?.attributes?.last_analysis_stats;
      return stats?.malicious || 0;
    }
  } catch (err) {
    logger.warn("VirusTotal API lookup failed", err);
  }
  return undefined;
}

/**
 * Main attachment inspector function.
 */
export async function inspectAttachments(
  attachments: AttachmentInput[],
  apiKey?: string
): Promise<{
  summary: { totalAttachments: number; maliciousCount: number; suspiciousCount: number };
  results: AttachmentAuditResult[];
}> {
  const results: AttachmentAuditResult[] = [];
  let maliciousCount = 0;
  let suspiciousCount = 0;

  for (const att of attachments) {
    const suspiciousTraits: string[] = [];

    let bytes: Uint8Array;
    let isBase64 = false;
    if (att.data) {
      try {
        bytes = Buffer.from(att.data, 'base64');
        isBase64 = true;
      } catch {
        bytes = new TextEncoder().encode(att.data);
      }
    } else {
      bytes = new Uint8Array(0);
    }

    const hashes = att.hash
      ? { sha256: att.hash, md5: '' }
      : await computeHashes(bytes.length > 0 ? bytes : att.filename, isBase64);

    const doubleExt = checkDoubleExtension(att.filename);
    if (doubleExt.hasDoubleExt) {
      suspiciousTraits.push(`Double extension spoof detected: '${att.filename}' ends with executable extension '${doubleExt.ext2}'`);
    }

    const ext = '.' + att.filename.split('.').pop()?.toLowerCase();
    const isExecExt = SCANNER_CONSTANTS.EXECUTABLE_EXTENSIONS.includes(ext);
    if (isExecExt) {
      suspiciousTraits.push(`Executable attachment extension: '${ext}'`);
    }

    let magicMatch = true;
    let detectedType: string | null = null;
    if (bytes.length >= 4) {
      const magicResult = verifyMagicBytes(att.filename, bytes);
      magicMatch = magicResult.match;
      detectedType = magicResult.detectedType;
      if (!magicMatch) {
        suspiciousTraits.push(`File extension mismatch: filename indicates '${ext}' but magic bytes match '${detectedType}'`);
      }
    }

    if (att.filename.toLowerCase().endsWith('.pdf') && bytes.length > 0) {
      const pdfTraits = scanPdfStructure(bytes);
      suspiciousTraits.push(...pdfTraits);
    }

    const vtHits = await checkVirusTotal(hashes.sha256, apiKey);
    if (vtHits && vtHits > 0) {
      suspiciousTraits.push(`Flagged by ${vtHits} VirusTotal security vendors`);
    }

    let threatLevel: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' = 'CLEAN';
    if ((vtHits && vtHits > 0) || doubleExt.hasDoubleExt || !magicMatch) {
      threatLevel = 'MALICIOUS';
      maliciousCount++;
    } else if (suspiciousTraits.length > 0 || isExecExt) {
      threatLevel = 'SUSPICIOUS';
      suspiciousCount++;
    }

    results.push({
      filename: att.filename,
      contentType: att.contentType,
      size: att.size || bytes.length,
      sha256: hashes.sha256,
      md5: hashes.md5,
      magicByteMatch: magicMatch,
      detectedType,
      hasDoubleExtension: doubleExt.hasDoubleExt,
      hasExecutableExtension: isExecExt,
      suspiciousTraits,
      threatLevel,
      virusTotalHits: vtHits
    });
  }

  return {
    summary: {
      totalAttachments: attachments.length,
      maliciousCount,
      suspiciousCount
    },
    results
  };
}
