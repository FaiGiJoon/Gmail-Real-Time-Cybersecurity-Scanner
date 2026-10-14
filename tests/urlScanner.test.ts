import { describe, expect, it } from 'bun:test';
import {
  isHomograph,
  isTyposquatted,
  isLinkTextMismatch,
  isIpHostname,
  levenshteinDistance,
  verifyUrlReputation
} from '../src/scanner/urlScanner.ts';

describe('URL Scanner', () => {
  it('calculates Levenshtein distance correctly', () => {
    expect(levenshteinDistance("kitten", "sitting")).toBe(3);
    expect(levenshteinDistance("spotify", "spotifi")).toBe(1);
    expect(levenshteinDistance("google", "google")).toBe(0);
  });

  it('detects Punycode homograph URLs', () => {
    expect(isHomograph("https://xn--e1afmkfd.xn--p1ai")).toBe(true);
    expect(isHomograph("https://spotify.com")).toBe(false);
  });

  it('detects typosquatted brand domains', () => {
    expect(isTyposquatted("https://spotifi.com")).toBe("spotify");
    expect(isTyposquatted("https://g0ogle.com")).toBe("google");
    expect(isTyposquatted("https://paypa1.com")).toBe("paypal");
    expect(isTyposquatted("https://spotify.com")).toBeNull();
  });

  it('detects anchor text and destination link mismatches', () => {
    expect(isLinkTextMismatch("https://www.google.com", "https://www.evil.com/login")).toBe(true);
    expect(isLinkTextMismatch("Google Search", "https://www.google.com")).toBe(false);
    expect(isLinkTextMismatch("spotify.com", "https://spotify.com/account")).toBe(false);
  });

  it('detects raw IP hostnames', () => {
    expect(isIpHostname("http://192.168.1.1/login")).toBe(true);
    expect(isIpHostname("https://spotify.com")).toBe(false);
  });

  it('evaluates verifyUrlReputation for multiple URLs', async () => {
    const result = await verifyUrlReputation([
      "https://spotifi.com/login",
      "https://spotify.com/account"
    ], "https://spotify.com");

    expect(result.summary.totalUrls).toBe(2);
    expect(result.summary.suspiciousCount + result.summary.maliciousCount).toBeGreaterThanOrEqual(1);
    expect(result.results[0].typosquattedBrand).toBe("spotify");
  });
});
