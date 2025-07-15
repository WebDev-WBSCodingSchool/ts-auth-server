import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { RefreshToken, User } from '#models';
import type { UserType } from '#models/User';
import { REFRESH_JWT_SECRET, SALT_ROUNDS } from '#config';
import { createTokens } from '#utils';
import type { RequestHandler } from 'express';
import type { z } from 'zod/v4';
import type { registerSchema, loginSchema } from '#schemas';

type RegisterDTO = z.infer<typeof registerSchema>;
type LoginDTO = z.infer<typeof loginSchema>;
type RefreshTokenDTO = {
  refreshToken: string;
};

type LogoutDTO = RefreshTokenDTO;

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

  const [refreshToken, accessToken] = await createTokens(user, service);

  res.status(201).json({ message: 'Registered', token: accessToken, refreshToken });
};

export const login: RequestHandler<unknown, SuccessResponseBody, LoginDTO> = async (req, res) => {
  const { email, password, service } = req.body;

  const user = await User.findOne({ email }).lean();
  if (!user) throw new Error('Incorrect credentials', { cause: { status: 401 } });

  const match = await bcrypt.compare(password, user.password);
  if (!match) throw new Error('Incorrect credentials', { cause: { status: 401 } });

  const [refreshToken, accessToken] = await createTokens(user, service);

  res.status(200).json({ message: 'Logged in', token: accessToken, refreshToken });
};

export const refresh: RequestHandler<unknown, SuccessResponseBody, RefreshTokenDTO> = async (
  req,
  res
) => {
  const { refreshToken } = req.body;
  if (!refreshToken) throw new Error('Refresh token is required.', { cause: { status: 401 } });

  let decoded: jwt.JwtPayload;
  try {
    decoded = jwt.verify(refreshToken, REFRESH_JWT_SECRET) as jwt.JwtPayload;
  } catch (error) {
    throw new Error('Invalid or expired refresh token.', { cause: { status: 403 } });
  }

  const { sub: userId, jti } = decoded;

  if (!userId || !jti) {
    throw new Error('Invalid token payload.', { cause: { status: 403 } });
  }

  const storedToken = await RefreshToken.findOne({ jti }).lean();
  if (!storedToken) {
    throw new Error('Refresh token not found.', { cause: { status: 403 } });
  }

  await RefreshToken.findByIdAndDelete(storedToken._id);

  const user = await User.findById(userId).lean();
  if (!user) {
    throw new Error('User not found.', { cause: { status: 403 } });
  }

  const [newRefreshToken, newAccessToken] = await createTokens(user, decoded.aud as string);

  res
    .status(200)
    .json({ message: 'Refreshed', token: newAccessToken, refreshToken: newRefreshToken });
};

export const logout: RequestHandler<unknown, { message: string }, LogoutDTO> = async (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    try {
      const decoded = jwt.verify(refreshToken, REFRESH_JWT_SECRET) as jwt.JwtPayload;
      if (decoded.jti) {
        await RefreshToken.deleteOne({ jti: decoded.jti });
      }
    } catch (error) {
      // The token is already unusable. We can ignore the error.
    }
  }

  res.status(200).json({ message: 'Successfully logged out' });
};
