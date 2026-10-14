/**
 * PII and Credential Masking Logger for Gmail Security Scanner.
 */

export class Logger {
  private logLevel: 'debug' | 'info' | 'warn' | 'error';

  constructor(logLevel: 'debug' | 'info' | 'warn' | 'error' = 'info') {
    this.logLevel = logLevel;
  }

  /**
   * Masks email addresses (e.g. "john.doe@example.com" -> "j***e@e***e.com")
   */
  public static maskEmail(email: string): string {
    return email.replace(/([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, (_match, user, domain) => {
      const maskedUser = user.length <= 2
        ? user[0] + '***'
        : user[0] + '***' + user[user.length - 1];
      const domainParts = domain.split('.');
      const mainDomain = domainParts[0];
      const maskedDomain = mainDomain.length <= 2
        ? mainDomain[0] + '***'
        : mainDomain[0] + '***' + mainDomain[mainDomain.length - 1];
      const tld = domainParts.slice(1).join('.');
      return `${maskedUser}@${maskedDomain}.${tld}`;
    });
  }

  /**
   * Masks sensitive credentials like API keys, bearer tokens, passwords.
   */
  public static maskCredentials(text: string): string {
    if (!text) return text;
    let masked = text;

    // Mask Google API keys (AIzaSy...)
    masked = masked.replace(/AIza[a-zA-Z0-9_-]{30,35}/g, '[REDACTED_API_KEY]');

    // Mask Bearer tokens
    masked = masked.replace(/Bearer\s+[a-zA-Z0-9._~+/-]+=*/gi, 'Bearer [REDACTED_TOKEN]');

    // Mask key/secret values in query params or JSON
    masked = masked.replace(/(api_?key|password|token|secret|auth)=([^&\s"']+)/gi, '$1=[REDACTED]');

    return masked;
  }

  /**
   * Sanitizes all string values in an object or primitives.
   */
  public static sanitize(input: unknown): unknown {
    if (typeof input === 'string') {
      return Logger.maskCredentials(Logger.maskEmail(input));
    }
    if (Array.isArray(input)) {
      return input.map(item => Logger.sanitize(item));
    }
    if (input !== null && typeof input === 'object') {
      const sanitizedObj: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(input)) {
        if (/password|token|secret|api_?key|auth/i.test(key)) {
          sanitizedObj[key] = '[REDACTED]';
        } else {
          sanitizedObj[key] = Logger.sanitize(value);
        }
      }
      return sanitizedObj;
    }
    return input;
  }

  private shouldLog(level: 'debug' | 'info' | 'warn' | 'error'): boolean {
    const levels = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.logLevel);
  }

  public debug(message: string, meta?: unknown): void {
    if (this.shouldLog('debug')) {
      console.debug(`[DEBUG] ${Logger.maskCredentials(Logger.maskEmail(message))}`, meta ? Logger.sanitize(meta) : '');
    }
  }

  public info(message: string, meta?: unknown): void {
    if (this.shouldLog('info')) {
      console.info(`[INFO] ${Logger.maskCredentials(Logger.maskEmail(message))}`, meta ? Logger.sanitize(meta) : '');
    }
  }

  public warn(message: string, meta?: unknown): void {
    if (this.shouldLog('warn')) {
      console.warn(`[WARN] ${Logger.maskCredentials(Logger.maskEmail(message))}`, meta ? Logger.sanitize(meta) : '');
    }
  }

  public error(message: string, meta?: unknown): void {
    if (this.shouldLog('error')) {
      console.error(`[ERROR] ${Logger.maskCredentials(Logger.maskEmail(message))}`, meta ? Logger.sanitize(meta) : '');
    }
  }
}

export const logger = new Logger(process.env.LOG_LEVEL as any || 'info');
