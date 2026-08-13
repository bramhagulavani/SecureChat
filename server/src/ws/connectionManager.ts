/**
 * Connection Manager
 * ------------------
 * Tracks which usernames currently have an open WebSocket connection.
 * Deliberately dumb: a Map from username to socket. No message content or
 * routing logic lives here — see messageRouter.ts for that.
 */

import type { WebSocket } from 'ws';

const connections = new Map<string, WebSocket>();

export function reset(): void {
  connections.clear();
}

export function addConnection(username: string, socket: WebSocket): void {
  connections.set(username, socket);
}

export function removeConnection(username: string): void {
  connections.delete(username);
}

export function getConnection(username: string): WebSocket | undefined {
  return connections.get(username);
}

export function isConnected(username: string): boolean {
  return connections.has(username);
}

export function connectedUsernames(): string[] {
  return Array.from(connections.keys());
}
