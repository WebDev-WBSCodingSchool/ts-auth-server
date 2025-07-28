import type { ErrorRequestHandler } from 'express';

type ErrorPayload = {
  message: string;
  code?: string;
};

const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  process.env.NODE_ENV !== 'production' && console.error(err.stack);
  if (err instanceof Error) {
    const payload: ErrorPayload = { message: err.message };
    if (err.cause) {
      const cause = err.cause as { status: number; code?: string };
      if (cause.code) payload.code = cause.code;
      res.status(cause.status ?? 500).json(payload);
      return;
    }
    res.status(500).json(payload);
    return;
  }
  res.status(500).json({ message: 'Internal server error' });
  return;
};

export default errorHandler;
