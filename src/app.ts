import '#db';
import express from 'express';
import cookieParser from 'cookie-parser';
import { authRouter } from '#routes';
import { errorHandler, notFoundHandler } from '#middlewares';

const app = express();
const port = process.env.PORT || '3000';

app.use(express.json(), cookieParser());

app.use('/auth', authRouter);

app.use('*splat', notFoundHandler);
app.use(errorHandler);

app.listen(port, () => {
  console.log(`Auth Server listening on port ${port}`);
});
