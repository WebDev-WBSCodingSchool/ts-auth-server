import { z } from 'zod/v4';

const envSchema = z.object({
  REFRESH_TOKEN_TTL: z.coerce.number().default(30 * 24 * 60 * 60), // 30 days
  ACCESS_TOKEN_TTL: z.coerce.number().default(15 * 60), // 15 minutes
  SALT_ROUNDS: z.coerce.number().default(13),

  ACCESS_JWT_SECRET: z
    .string({
      error: 'ACCESS_JWT_SECRET is required and must be at least 64 characters long'
    })
    .min(64),
  REFRESH_JWT_SECRET: z
    .string({
      error: 'REFRESH_JWT_SECRET is required and must be at least 64 characters long'
    })
    .min(64),
  JWT_ISSUER: z.string().default('https://www.wbscodingschool.com/')
});

const parsedEnv = envSchema.safeParse(process.env);

if (!parsedEnv.success) {
  console.error('❌ Invalid environment variables:\n', z.prettifyError(parsedEnv.error));
  process.exit(1);
}

export const {
  REFRESH_TOKEN_TTL,
  ACCESS_TOKEN_TTL,
  SALT_ROUNDS,
  ACCESS_JWT_SECRET,
  REFRESH_JWT_SECRET,
  JWT_ISSUER
} = parsedEnv.data;
