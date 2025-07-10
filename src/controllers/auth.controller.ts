import bcrypt from 'bcrypt';
import { RefreshToken, User } from '#models';
import { SALT_ROUNDS } from '#config';
import { signJWT } from '#utils';
import type { RequestHandler } from 'express';
import type { z } from 'zod/v4';
import type { registerSchema, loginSchema } from '#schemas';

type RegisterDTO = z.infer<typeof registerSchema>;
type LoginDTO = z.infer<typeof loginSchema>;

type SuccessResponseBody = {
  token: string;
  refreshToken?: string;
  message?: string;
};

export const register: RequestHandler<unknown, SuccessResponseBody, RegisterDTO> = async (
  req,
  res
) => {
  const { email, password, service } = req.body;

  const userExists = await User.exists({ email });
  if (userExists) throw new Error('Email already exists', { cause: { status: 409 } });

  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  const hashedPW = await bcrypt.hash(password, salt);

  const user = await User.create({ email, password: hashedPW });

  const [refreshToken, sessionId, jti] = signJWT({}, user._id.toString(), service, 'refresh');

  const refreshTokenEntry = await RefreshToken.create({
    token: refreshToken,
    userId: user._id,
    sessionId,
    jti
  });

  const [accessToken] = signJWT(
    { roles: user.roles },
    user._id.toString(),
    service,
    'access',
    sessionId
  );

  res.status(201).json({ message: 'Registered', token: accessToken, refreshToken });
};

export const login: RequestHandler<unknown, SuccessResponseBody, LoginDTO> = async (req, res) => {
  const { email, password, service } = req.body;

  const user = await User.findOne({ email }).lean();
  if (!user) throw new Error('Incorrect credentials', { cause: { status: 401 } });

  const match = await bcrypt.compare(password, user.password);
  if (!match) throw new Error('Incorrect credentials', { cause: { status: 401 } });

  const [refreshToken, sessionId, jti] = signJWT({}, user._id.toString(), service, 'refresh');

  const refreshTokenEntry = await RefreshToken.create({
    token: refreshToken,
    userId: user._id,
    sessionId,
    jti
  });

  const [accessToken] = signJWT(
    { roles: user.roles },
    user._id.toString(),
    service,
    'access',
    sessionId
  );

  res.status(200).json({ message: 'Logged in', token: accessToken, refreshToken });
};

export const refresh: RequestHandler = async (req, res) => {
  res.status(200).json({ message: 'Refreshed' });
};

export const logout: RequestHandler = async (req, res) => {
  res.status(200).json({ message: 'Logged out' });
};
