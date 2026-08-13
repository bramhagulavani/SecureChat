/**
 * SecureChat Relay Server — entry point.
 *
 * Combines the HTTP API (registration, prekey bundles) and the WebSocket
 * relay (ciphertext routing) on one server.
 *
 * Security invariant for this whole package: no function in `server/`
 * should ever import a decryption routine from `crypto-core`. The server
 * package doesn't even list crypto-core as a dependency, so this can't
 * happen by accident.
 *
 * Known simplification, flagged for follow-up: the WebSocket handshake
 * identifies a user via a `?username=` query param with no auth token or
 * signature check. That's fine for local development and the tests in this
 * package, but is NOT sufficient for a real deployment — anyone could claim
 * any username and receive their queued messages. Proper auth (e.g. a
 * signed challenge using the user's identity key, or a session token issued
 * at registration) needs to land before this touches real users.
 */

import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { createApp } from './app';
import { addConnection, removeConnection } from './ws/connectionManager';
import { deliverQueuedMessages, routeMessage, IncomingRelayMessage } from './ws/messageRouter';

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

export function startServer(port: number = PORT): http.Server {
  const app = createApp();
  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });

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
