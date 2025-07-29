import type { Response } from 'express';
import {
  ACCESS_JWT_SECRET,
  ACCESS_TOKEN_TTL,
  REFRESH_JWT_SECRET,
  REFRESH_TOKEN_TTL,
  SALT_ROUNDS
} from '#config';
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
  // TODO: Implement user registration
  // Make sure to securely hash the password and storing only the hash
  // Issue an access and a refresh token and put them in cookies
  // Also store the refresh token in your db
};

export const login: RequestHandler<unknown, SuccessResponseBody, LoginDTO> = async (req, res) => {
  // TODO: Implement user login
  // Check if the user exists in the database
  // Compare the password from the request with the hash in your db
  // Send an Error "Incorrect credentials" if either no user is found (invalid email) or the password is incorrect
  // Issue tokens and put them into cookies
  // Also store the refresh token in your db
};

export const refresh: RequestHandler<unknown, SuccessResponseBody, RefreshTokenDTO> = async (
  req,
  res
) => {
  // TODO: Implement access token refresh and refresh token rotation
  // Get the refresh token from the cookies and verify it
  // Look up the refresh token in the database, throw and error, if it canot be found
  // delete the old refresh token, look up the user and issue new tokens
  // store the new refresh token in your db and send both access and refresh token via cookies
};

export const logout: RequestHandler<unknown, { message: string }, LogoutDTO> = async (req, res) => {
  // TODO: Implement logout by removing the tokens
  // Get the tokens from the cookies
  // Delete the refresh token from your database
  // Clear both cookies
  // A longer living access token, or a token in a higher risk use case would need to be put on a token blacklist - another entry in your db - and checked on validation
  // Since our access tokens are valid for a couple of minutes the risk here is acceptable
};

export const me: RequestHandler<unknown, unknown, ValidateTokenDTO> = async (req, res, next) => {
  // TODO: Implement a me handler
  // Get the access token and use it to retrieve the user's data
  // Make sure that the token is valid and not expired
  // When expired, send a WWW-Authenticate Header with a 'token_expired' payload
};
