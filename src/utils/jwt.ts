import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { ACCESS_JWT_SECRET, ACCESS_TOKEN_TTL, JWT_ISSUER } from '#config';
import { RefreshToken } from '#models';
import type { UserType } from '#models/User';

export const signJWT = (payload: {}, subject: string, audience: string | undefined): string => {
  const secret = ACCESS_JWT_SECRET;
  const expiresIn = ACCESS_TOKEN_TTL;

  const options: { audience?: string } = {};
  if (audience) options.audience = audience;

  const token = jwt.sign(payload, secret, {
    expiresIn,
    issuer: JWT_ISSUER,
    subject,
    ...options
  });

  return token;
};

export const createTokens = async (user: UserType): Promise<[string, string]> => {
  const refreshToken = randomUUID();

  await RefreshToken.create({
    token: refreshToken,
    userId: user._id
  });

  const accessToken = signJWT({ roles: user.roles }, user._id.toString(), 'access');

  return [refreshToken, accessToken];
};
