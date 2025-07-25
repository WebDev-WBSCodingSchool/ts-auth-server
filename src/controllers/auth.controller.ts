import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { RefreshToken, TokenBlacklist, User } from '#models';
import { ACCESS_JWT_SECRET, REFRESH_JWT_SECRET, SALT_ROUNDS } from '#config';
import { createTokens } from '#utils';
import type { RequestHandler } from 'express';
import type { z } from 'zod/v4';
import type { registerSchema, loginSchema } from '#schemas';

type RegisterDTO = z.infer<typeof registerSchema>;
type LoginDTO = z.infer<typeof loginSchema>;
type RefreshTokenDTO = {
  refreshToken?: string;
  accessToken?: string;
};

type LogoutDTO = RefreshTokenDTO;
type ValidateTokenDTO = {
  accessToken?: string;
};

type SuccessResponseBody = {
  accessToken: string;
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

  res.status(201).json({ message: 'Registered', accessToken, refreshToken });
};

export const login: RequestHandler<unknown, SuccessResponseBody, LoginDTO> = async (req, res) => {
  const { email, password, service } = req.body;

  const user = await User.findOne({ email }).lean();
  if (!user) throw new Error('Incorrect credentials', { cause: { status: 401 } });

  const match = await bcrypt.compare(password, user.password);
  if (!match) throw new Error('Incorrect credentials', { cause: { status: 401 } });

  const [refreshToken, accessToken] = await createTokens(user, service);

  res.status(200).json({ message: 'Logged in', accessToken, refreshToken });
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
    .json({ message: 'Refreshed', accessToken: newAccessToken, refreshToken: newRefreshToken });
};

export const logout: RequestHandler<unknown, { message: string }, LogoutDTO> = async (req, res) => {
  const { refreshToken, accessToken } = req.body;

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

  if (accessToken) {
    try {
      const decoded = jwt.verify(accessToken, ACCESS_JWT_SECRET) as jwt.JwtPayload;

      if (decoded.jti && decoded.exp) {
        const expireAt = new Date(decoded.exp * 1000);
        await TokenBlacklist.create({
          jti: decoded.jti,
          userId: decoded.sub,
          expireAt
        });
      }
    } catch (error) {
      // The token is invalid anyway. We can ignore the error.
    }
  }

  res.status(200).json({ message: 'Successfully logged out' });
};

export const validateToken: RequestHandler<unknown, unknown, ValidateTokenDTO> = async (
  req,
  res,
  next
) => {
  const { accessToken } = req.body;
  if (!accessToken) throw new Error('Access token is required.', { cause: { status: 401 } });

  try {
    const decoded = jwt.verify(accessToken, ACCESS_JWT_SECRET) as jwt.JwtPayload;
    if (!decoded.jti) throw new Error();
    const isOnBlacklist = await TokenBlacklist.exists({ jti: decoded.jti });
    if (isOnBlacklist) throw new Error();
  } catch (error) {
    if (
      error &&
      typeof error === 'object' &&
      'name' in error &&
      (error as { name?: string }).name === 'TokenExpiredError'
    ) {
      return next(new Error('Expired access token', { cause: { status: 401 } }));
    }
    return next(new Error('Invalid access token.', { cause: { status: 401 } }));
  }

  res.status(200).json({ message: 'Valid token' });
};

export const me: RequestHandler<unknown, unknown, ValidateTokenDTO> = async (req, res, next) => {
  const { accessToken } = req.body;
  if (!accessToken) throw new Error('Access token is required.', { cause: { status: 401 } });

  try {
    const decoded = jwt.verify(accessToken, ACCESS_JWT_SECRET) as jwt.JwtPayload;
    if (!decoded.jti || !decoded.sub)
      throw new Error('Invalid or expired access token.', { cause: { status: 403 } });
    const isOnBlacklist = await TokenBlacklist.exists({ jti: decoded.jti });
    if (isOnBlacklist)
      throw new Error('Invalid or expired access token.', { cause: { status: 403 } });
    const user = await User.findById(decoded.sub).select('-password');
    if (!user) throw new Error('User not found', { cause: { status: 404 } });

    res.status(200).json({ message: 'Valid token', user });
  } catch (error) {
    next(error);
  }
};
