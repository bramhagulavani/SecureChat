/**
 * SecureChat Relay Server — entry point.
 *
 * Combines the HTTP API (registration, prekey bundles, auth challenges) and
 * the WebSocket relay (ciphertext routing) on one server.
 *
 * Security invariants:
 *   - No decryption capability: `server/` never imports `crypto-core` and has
 *     zero decryption capability.
 *   - Signed-challenge auth: WebSocket connections must present a valid
 *     signature over a freshly-issued single-use challenge signed with the
 *     user's identity signing private key. Verified via `tweetnacl` in
 *     `verifyClient`.
 */

import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { createApp } from './app';
import { addConnection, removeConnection } from './ws/connectionManager';
import { deliverQueuedMessages, routeMessage, IncomingRelayMessage } from './ws/messageRouter';
import { getIdentitySigningPublicKey } from './store/userStore';
import { consumeChallenge } from './auth/challengeStore';
import { verifyAuthSignature } from './auth/verifySignature';

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

export function startServer(port: number = PORT): http.Server {
  const app = createApp();
  const server = http.createServer(app);

  const wss = new WebSocketServer({
    server,
    path: '/ws',
    verifyClient: (info, callback) => {
      try {
        const url = new URL(info.req.url ?? '', 'http://localhost');
        const username = url.searchParams.get('username');
        const signature = url.searchParams.get('signature');

        if (!username || !signature) {
          callback(false, 401, 'Unauthorized: username and signature query params are required');
          return;
        }

        const signingPublicKey = getIdentitySigningPublicKey(username);
        if (!signingPublicKey) {
          callback(false, 401, 'Unauthorized: user not registered');
          return;
        }

        const challenge = consumeChallenge(username);
        if (!challenge) {
          callback(false, 401, 'Unauthorized: invalid or expired challenge');
          return;
        }

        const isValid = verifyAuthSignature(challenge, signature, signingPublicKey);
        if (!isValid) {
          callback(false, 401, 'Unauthorized: invalid signature');
          return;
        }

        callback(true);
      } catch {
        callback(false, 500, 'Internal server error during auth verification');
      }
    },
  });

  wss.on('connection', (socket: WebSocket, request) => {
    const url = new URL(request.url ?? '', 'http://localhost');
    const username = url.searchParams.get('username');

    if (!username) {
      socket.close(4000, 'username query param is required');
      return;
    }

    addConnection(username, socket);
    deliverQueuedMessages(username, socket);

    socket.on('message', (data) => {
      let parsed: IncomingRelayMessage;
      try {
        parsed = JSON.parse(data.toString());
      } catch {
        socket.send(JSON.stringify({ type: 'error', error: 'Invalid JSON' }));
        return;
      }
      if (!parsed || typeof parsed.to !== 'string') {
        socket.send(JSON.stringify({ type: 'error', error: 'Message must include a "to" field' }));
        return;
      }
      routeMessage(username, parsed);
    });

    socket.on('close', () => {
      removeConnection(username);
    });
  });

  server.listen(port, () => {
    console.log(`SecureChat relay server listening on port ${port}`);
  });

  return server;
}

if (require.main === module) {
  startServer();
}
