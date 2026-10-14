import dotenv from 'dotenv';
import { configSchema, type Config } from '../schemas/index.ts';

dotenv.config();

export function loadConfig(): Config {
  const result = configSchema.safeParse(process.env);
  if (!result.success) {
    console.warn('[CONFIG] Warning: Invalid environment configuration, using defaults.', result.error.format());
    return configSchema.parse({});
  }
  return result.data;
}

export const config = loadConfig();
