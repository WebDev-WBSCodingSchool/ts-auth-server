import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import {
  ACCESS_JWT_SECRET,
  ACCESS_TOKEN_TTL,
  REFRESH_JWT_SECRET,
  REFRESH_TOKEN_TTL,
  JWT_ISSUER
} from '#config';

type token = string;
type sessionId = string;
type jti = string;

export const signJWT = (
  payload: {},
  subject: string,
  audience: string | undefined,
  type: 'refresh' | 'access',
  sessionId: string | undefined = undefined
): [token, sessionId, jti] => {
  const secret = type === 'access' ? ACCESS_JWT_SECRET : REFRESH_JWT_SECRET;
  const expiresIn = type === 'access' ? ACCESS_TOKEN_TTL : REFRESH_TOKEN_TTL;

  const session = sessionId ?? randomUUID();
  const jwtid = randomUUID();
  const appliedPayload = { ...payload, session };

  const options: { audience?: string } = {};
  if (audience) options.audience = audience;

  const token = jwt.sign(appliedPayload, secret, {
    expiresIn,
    issuer: JWT_ISSUER,
    subject,
    jwtid,
    ...options
  });

  return [token, session, jwtid];
};
