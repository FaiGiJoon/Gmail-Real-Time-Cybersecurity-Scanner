import { describe, expect, it } from 'bun:test';
import { Logger } from '../src/utils/logger.ts';

describe('PII Logger', () => {
  it('masks email addresses correctly', () => {
    const masked1 = Logger.maskEmail("john.doe@spotify.com");
    expect(masked1).not.toContain("john.doe");
    expect(masked1).toContain("@");

    const masked2 = Logger.maskEmail("a@b.com");
    expect(masked2).toBe("a***@b***.com");
  });

  it('masks sensitive API keys and tokens', () => {
    const secretText = "Key is AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6 and Bearer secret_token_12345";
    const masked = Logger.maskCredentials(secretText);

    expect(masked).not.toContain("AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6");
    expect(masked).toContain("[REDACTED_API_KEY]");
    expect(masked).toContain("Bearer [REDACTED_TOKEN]");
  });

  it('sanitizes objects recursively', () => {
    const inputObj = {
      userEmail: "alice@example.com",
      password: "SuperSecretPassword123",
      apiKey: "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    };

    const sanitized = Logger.sanitize(inputObj) as any;
    expect(sanitized.password).toBe("[REDACTED]");
    expect(sanitized.apiKey).toBe("[REDACTED]");
    expect(sanitized.userEmail).not.toContain("alice@example.com");
  });
});
