/**
 * Express App
 * -----------
 * Separated from index.ts so tests can import the app directly (via
 * supertest) without binding a real port.
 */

import express, { Express } from 'express';
import { usersRouter } from './api/users.routes';

export function createApp(): Express {
  const app = express();
  app.use(express.json());

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.use('/users', usersRouter);

  return app;
}
