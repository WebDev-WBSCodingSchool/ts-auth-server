import '#db';
import cors from 'cors';
import express from 'express';
import cookieParser from 'cookie-parser';
import { authRouter } from '#routes';
import { errorHandler, notFoundHandler } from '#middlewares';
import { CLIENT_BASE_URL } from '#config';

const app = express();
const port = process.env.PORT || '3000';

app.use(
  cors({
    origin: CLIENT_BASE_URL,
    credentials: true,
    exposedHeaders: ['WWW-Authenticate']
  })
);

app.use(express.json(), cookieParser());

app.use('/auth', authRouter);

app.use('*splat', notFoundHandler);
app.use(errorHandler);

app.listen(port, () => {
  console.log(`Auth Server listening on port ${port}`);
});
