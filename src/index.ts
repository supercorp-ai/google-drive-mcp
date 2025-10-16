#!/usr/bin/env node

import { hideBin } from 'yargs/helpers'
import yargs from 'yargs'
import express, { Request, Response as ExpressResponse } from 'express'
import cors from 'cors'
import type { CorsOptionsDelegate } from 'cors'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { InMemoryEventStore } from '@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js'
import { z } from 'zod'
import { google, drive_v3 } from 'googleapis'
import { OAuth2Client } from 'google-auth-library'
import { Redis } from '@upstash/redis'
import { randomUUID } from 'node:crypto'

// --------------------------------------------------------------------
// Helper: JSON Response Formatter
// --------------------------------------------------------------------
function toTextJson(data: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(data, null, 2)
      }
    ]
  };
}

// --------------------------------------------------------------------
// Configuration & Storage Interface
// --------------------------------------------------------------------
interface Config {
  port: number;
  transport: 'sse' | 'stdio' | 'http';
  httpMode: 'stateful' | 'stateless';
  storage: 'memory-single' | 'memory' | 'upstash-redis-rest';
  googleClientId: string;
  googleClientSecret: string;
  googleRedirectUri: string;
  storageHeaderKey?: string;
  upstashRedisRestUrl?: string;
  upstashRedisRestToken?: string;
}

interface Storage {
  get(memoryKey: string): Promise<Record<string, any> | undefined>;
  set(memoryKey: string, data: Record<string, any>): Promise<void>;
}

// --------------------------------------------------------------------
// In-Memory Storage Implementation
// --------------------------------------------------------------------
class MemoryStorage implements Storage {
  private storage: Record<string, Record<string, any>> = {};

  async get(memoryKey: string) {
    return this.storage[memoryKey];
  }

  async set(memoryKey: string, data: Record<string, any>) {
    // Merge new data with existing data so that previous tokens are preserved.
    this.storage[memoryKey] = { ...this.storage[memoryKey], ...data };
  }
}

// --------------------------------------------------------------------
// Upstash Redis Storage Implementation
// --------------------------------------------------------------------
class RedisStorage implements Storage {
  private redis: Redis;
  private keyPrefix: string;

  constructor(redisUrl: string, redisToken: string, keyPrefix: string) {
    this.redis = new Redis({ url: redisUrl, token: redisToken });
    this.keyPrefix = keyPrefix;
  }

  async get(memoryKey: string): Promise<Record<string, any> | undefined> {
    const data = await this.redis.get(`${this.keyPrefix}:${memoryKey}`);
    if (data === null) return undefined;
    if (typeof data === 'string') {
      try { return JSON.parse(data); } catch { return undefined; }
    }
    return data as any;
  }

  async set(memoryKey: string, data: Record<string, any>) {
    const existing = (await this.get(memoryKey)) || {};
    const newData = { ...existing, ...data };
    await this.redis.set(`${this.keyPrefix}:${memoryKey}`, JSON.stringify(newData));
  }
}

// --------------------------------------------------------------------
// Google Drive OAuth & API Helpers
// --------------------------------------------------------------------
function getDriveScopes(): string[] {
  return [
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/drive.file'
  ];
}

/**
 * Creates an OAuth2 client using stored credentials.
 * If an access token is stored, it is set on the client.
 */
async function createOAuth2Client(config: Config, storage: Storage, memoryKey: string): Promise<OAuth2Client> {
  const client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
  const stored = await storage.get(memoryKey);
  if (stored && stored.accessToken) {
    client.setCredentials({ access_token: stored.accessToken });
  }
  return client;
}

async function getDriveClient(config: Config, storage: Storage, memoryKey: string): Promise<drive_v3.Drive> {
  const oauth2Client = await createOAuth2Client(config, storage, memoryKey);
  return google.drive({ version: 'v3', auth: oauth2Client });
}

/**
 * Returns an OAuth URL for initiating Drive authentication.
 */
function getAuthUrl(config: Config): string {
  return config.googleRedirectUri
  // const client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
  // return client.generateAuthUrl({
  //   access_type: 'offline',
  //   prompt: 'consent',
  //   scope: getDriveScopes(),
  // });
}

/**
 * Saves an access token provided by the client.
 * Merges with any previously stored tokens.
 */
async function saveToken(token: string, config: Config, storage: Storage, memoryKey: string): Promise<string> {
  let client: OAuth2Client;
  try {
    client = await createOAuth2Client(config, storage, memoryKey);
  } catch {
    client = new OAuth2Client(config.googleClientId, config.googleClientSecret, config.googleRedirectUri);
  }
  client.setCredentials({ access_token: token });
  await storage.set(memoryKey, { accessToken: token });
  return token;
}

// --------------------------------------------------------------------
// Google Drive API Methods
// --------------------------------------------------------------------
async function listFiles(
  args: { pageSize?: number; query?: string } = {},
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<{ nextPageToken?: string | null; files?: drive_v3.Schema$File[] } | { error: string }> {
  try {
    const drive = await getDriveClient(config, storage, memoryKey);
    const { pageSize = 10, query = '' } = args;
    const res = await drive.files.list({
      pageSize,
      q: query,
      fields: 'nextPageToken, files(id, name, mimeType, modifiedTime)'
    });
    return { nextPageToken: res.data.nextPageToken, files: res.data.files };
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

async function getFileMetadata(
  fileId: string,
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<drive_v3.Schema$File | { error: string }> {
  try {
    const drive = await getDriveClient(config, storage, memoryKey);
    const res = await drive.files.get({
      fileId,
      fields: 'id, name, mimeType, modifiedTime, webViewLink'
    });
    return res.data;
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

async function readFile(
  params: { fileId: string; exportMimeType?: string; config: Config; storage: Storage; memoryKey: string }
): Promise<{ content?: string } | { error: string }> {
  const { fileId, exportMimeType, config, storage, memoryKey } = params;
  try {
    const drive = await getDriveClient(config, storage, memoryKey);
    const meta = await drive.files.get({ fileId, fields: 'mimeType' });
    const fileMimeType = meta.data.mimeType;
    const exportMimeMap: { [key: string]: string } = {
      'application/vnd.google-apps.document': 'text/plain',
      'application/vnd.google-apps.spreadsheet': 'text/csv',
      'application/vnd.google-apps.presentation': 'application/pdf'
    };
    if (fileMimeType && exportMimeMap[fileMimeType]) {
      const mimeToUse = exportMimeType || exportMimeMap[fileMimeType];
      const res = await drive.files.export({ fileId, mimeType: mimeToUse }, { responseType: 'text' });
      return { content: res.data as string };
    } else {
      const res = await drive.files.get({ fileId, alt: 'media' }, { responseType: 'text' });
      return { content: res.data as string };
    }
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

async function moveFile(
  fileId: string,
  newFolderId: string,
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<{ id?: string; parents?: string[] } | { error: string }> {
  try {
    const drive = await getDriveClient(config, storage, memoryKey);
    const file = await drive.files.get({ fileId, fields: 'parents' });
    const previousParents = file.data.parents?.join(',') || '';
    const res = await drive.files.update({
      fileId,
      addParents: newFolderId,
      removeParents: previousParents,
      fields: 'id, parents'
    });
    return { id: res.data.id === null ? undefined : res.data.id, parents: res.data.parents ?? undefined };
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

async function createFile(
  args: { name: string; mimeType?: string; content: string; parents?: string[] },
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<drive_v3.Schema$File | { error: string }> {
  try {
    const drive = await getDriveClient(config, storage, memoryKey);
    const res = await drive.files.create({
      requestBody: {
        name: args.name,
        mimeType: args.mimeType || 'text/plain',
        ...(args.parents ? { parents: args.parents } : {})
      },
      media: {
        mimeType: args.mimeType || 'text/plain',
        body: args.content
      }
    });
    return res.data;
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

async function updateFile(
  args: { fileId: string; name?: string; mimeType?: string; content: string },
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<drive_v3.Schema$File | { error: string }> {
  try {
    const drive = await getDriveClient(config, storage, memoryKey);
    const res = await drive.files.update({
      fileId: args.fileId,
      requestBody: {
        ...(args.name ? { name: args.name } : {}),
        ...(args.mimeType ? { mimeType: args.mimeType } : {})
      },
      media: {
        mimeType: args.mimeType || 'text/plain',
        body: args.content
      }
    });
    return res.data;
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

async function deleteFile(
  fileId: string,
  config: Config,
  storage: Storage,
  memoryKey: string
): Promise<{ success: boolean } | { error: string }> {
  try {
    const drive = await getDriveClient(config, storage, memoryKey);
    await drive.files.delete({ fileId });
    return { success: true };
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

// --------------------------------------------------------------------
// MCP Server Creation: Register Google Drive Tools
// --------------------------------------------------------------------
function createMcpServer(memoryKey: string, config: Config, toolsPrefix: string): McpServer {
  const server = new McpServer({
    name: `Google Drive MCP Server (Memory Key: ${memoryKey})`,
    version: '1.0.0'
  });
  const storage: Storage = config.storage === 'upstash-redis-rest'
    ? new RedisStorage(config.upstashRedisRestUrl!, config.upstashRedisRestToken!, config.storageHeaderKey!)
    : new MemoryStorage();

  server.tool(
    `${toolsPrefix}auth_url`,
    'Return an OAuth URL for Google Drive. Visit this URL to grant access.',
    {
      // TODO: MCP SDK bug patch - remove when fixed
      comment: z.string().optional(),
    },
    async () => {
      try {
        const url = getAuthUrl(config);
        return toTextJson({ authUrl: url });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}save_token`,
    'Save an access token from the client for Google Drive access.',
    { token: z.string() },
    async ({ token }) => {
      try {
        await saveToken(token, config, storage, memoryKey);
        return toTextJson({ success: true });
      } catch (err: any) {
        return toTextJson({ error: String(err.message) });
      }
    }
  );

  server.tool(
    `${toolsPrefix}list_files`,
    'List files in Google Drive.',
    {
      pageSize: z.number().optional(),
      query: z.string().optional().describe(`
Basic query syntax:
  <query_term> <operator> <value>
  - query_term: a field like name, mimeType, modifiedTime, starred, trashed, parents, owners, fullText, appProperties, etc.
  - operator: one of =, !=, >, <, >=, <=, contains, in
  - value: strings in single quotes (e.g. 'hello'), dates in RFC 3339 (e.g. '2025-04-22T00:00:00Z'), IDs in quotes.
    `)
    },
    async (args) => {
      const result = await listFiles(args, config, storage, memoryKey);
      return toTextJson(result);
    }
  );

  server.tool(
    `${toolsPrefix}get_file_metadata`,
    'Get metadata for a specific file.',
    { fileId: z.string() },
    async ({ fileId }) => {
      const result = await getFileMetadata(fileId, config, storage, memoryKey);
      return toTextJson(result);
    }
  );

  server.tool(
    `${toolsPrefix}read_file`,
    'Read file content from Google Drive.',
    { fileId: z.string(), exportMimeType: z.string().optional() },
    async ({ fileId, exportMimeType }) => {
      const result = await readFile({ fileId, exportMimeType, config, storage, memoryKey });
      return toTextJson(result);
    }
  );

  server.tool(
    `${toolsPrefix}create_file`,
    'Create a new file on Google Drive.',
    { name: z.string(), mimeType: z.string().optional(), content: z.string(), parents: z.array(z.string()).optional() },
    async (args) => {
      const result = await createFile(args, config, storage, memoryKey);
      return toTextJson(result);
    }
  );

  server.tool(
    `${toolsPrefix}update_file`,
    'Update an existing file on Google Drive.',
    { fileId: z.string(), name: z.string().optional(), mimeType: z.string().optional(), content: z.string() },
    async (args) => {
      const result = await updateFile(args, config, storage, memoryKey);
      return toTextJson(result);
    }
  );

  server.tool(
    `${toolsPrefix}delete_file`,
    'Delete a file from Google Drive.',
    { fileId: z.string() },
    async ({ fileId }) => {
      const result = await deleteFile(fileId, config, storage, memoryKey);
      return toTextJson(result);
    }
  );

  server.tool(
    `${toolsPrefix}move_file`,
    'Move a file to a new folder on Google Drive.',
    { fileId: z.string(), newFolderId: z.string() },
    async ({ fileId, newFolderId }) => {
      const result = await moveFile(fileId, newFolderId, config, storage, memoryKey);
      return toTextJson(result);
    }
  );

  return server;
}

// --------------------------------------------------------------------
// Minimal Fly.io "replay" handling (optional)
// --------------------------------------------------------------------
function parseFlyReplaySrc(headerValue: string): Record<string, string> {
  const regex = /(.*?)=(.*?)($|;)/g;
  const matches = headerValue.matchAll(regex);
  const result: Record<string, string> = {};
  for (const match of matches) {
    if (match.length >= 3) {
      result[match[1].trim()] = match[2].trim();
    }
  }
  return result;
}
let machineId: string | null = null;
function saveMachineId(req: Request) {
  if (machineId) return;
  const headerKey = 'fly-replay-src';
  const raw = req.headers[headerKey.toLowerCase()];
  if (!raw || typeof raw !== 'string') return;
  try {
    const parsed = parseFlyReplaySrc(raw);
    if (parsed.state) {
      const decoded = decodeURIComponent(parsed.state);
      const obj = JSON.parse(decoded);
      if (obj.machineId) machineId = obj.machineId;
    }
  } catch {
    // ignore
  }
}

// --------------------------------------------------------------------
// Main: Start the server (HTTP / SSE / stdio) with CLI validations
// --------------------------------------------------------------------
async function main() {
  const argv = yargs(hideBin(process.argv))
    .option('port', { type: 'number', default: 8000 })
    .option('transport', { type: 'string', choices: ['sse', 'stdio', 'http'], default: 'sse' })
    .option('httpMode', {
      type: 'string',
      choices: ['stateful', 'stateless'] as const,
      default: 'stateful',
      describe:
        'Choose HTTP session mode when --transport=http. "stateful" uses MCP session IDs; "stateless" treats each request separately.'
    })
    .option('storage', {
      type: 'string',
      choices: ['memory-single', 'memory', 'upstash-redis-rest'],
      default: 'memory-single',
      describe:
        'Choose storage backend: "memory-single" uses fixed single-user storage; "memory" uses multi-user in-memory storage (requires --storageHeaderKey); "upstash-redis-rest" uses Upstash Redis (requires --storageHeaderKey, --upstashRedisRestUrl, and --upstashRedisRestToken).'
    })
    .option('googleClientId', { type: 'string', demandOption: true, describe: "Google Client ID" })
    .option('googleClientSecret', { type: 'string', demandOption: true, describe: "Google Client Secret" })
    .option('googleRedirectUri', { type: 'string', demandOption: true, describe: "Google Redirect URI" })
    .option('toolsPrefix', { type: 'string', default: 'google_drive_', describe: 'Prefix to add to all tool names.' })
    .option('storageHeaderKey', { type: 'string', describe: 'For storage "memory" or "upstash-redis-rest": the header name (or key prefix) to use.' })
    .option('upstashRedisRestUrl', { type: 'string', describe: 'Upstash Redis REST URL (if --storage=upstash-redis-rest)' })
    .option('upstashRedisRestToken', { type: 'string', describe: 'Upstash Redis REST token (if --storage=upstash-redis-rest)' })
    .help()
    .parseSync();

  const config: Config = {
    port: argv.port,
    transport: argv.transport as 'sse' | 'stdio' | 'http',
    httpMode: (argv.httpMode as 'stateful' | 'stateless') || 'stateful',
    storage: argv.storage as 'memory-single' | 'memory' | 'upstash-redis-rest',
    googleClientId: argv.googleClientId,
    googleClientSecret: argv.googleClientSecret,
    googleRedirectUri: argv.googleRedirectUri,
    storageHeaderKey:
      (argv.storage === 'memory-single')
        ? undefined
        : (argv.storageHeaderKey && argv.storageHeaderKey.trim()
            ? argv.storageHeaderKey.trim()
            : (() => { console.error('Error: --storageHeaderKey is required for storage modes "memory" or "upstash-redis-rest".'); process.exit(1); return ''; })()),
    upstashRedisRestUrl: argv.upstashRedisRestUrl,
    upstashRedisRestToken: argv.upstashRedisRestToken,
  };

  // Additional CLI validation:
  if ((argv.upstashRedisRestUrl || argv.upstashRedisRestToken) && config.storage !== 'upstash-redis-rest') {
    console.error("Error: --upstashRedisRestUrl and --upstashRedisRestToken can only be used when --storage is 'upstash-redis-rest'.");
    process.exit(1);
  }
  if (config.storage === 'upstash-redis-rest') {
    if (!config.upstashRedisRestUrl || !config.upstashRedisRestUrl.trim()) {
      console.error("Error: --upstashRedisRestUrl is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
    if (!config.upstashRedisRestToken || !config.upstashRedisRestToken.trim()) {
      console.error("Error: --upstashRedisRestToken is required for storage mode 'upstash-redis-rest'.");
      process.exit(1);
    }
  }

  const storageHeaderKeyLower = config.storageHeaderKey?.toLowerCase();
  const corsBaseHeaders = [
    'Content-Type',
    'Accept',
    'Mcp-Session-Id',
    'mcp-session-id',
    config.storageHeaderKey,
    storageHeaderKeyLower
  ].filter((header): header is string => typeof header === 'string' && header.length > 0);
  const corsOptionsDelegate: CorsOptionsDelegate<Request> = (req, callback) => {
    const headers = new Set<string>(corsBaseHeaders);
    const requestHeaders = req.header('Access-Control-Request-Headers');
    if (requestHeaders) {
      for (const header of requestHeaders.split(',')) {
        const trimmed = header.trim();
        if (trimmed) headers.add(trimmed);
      }
    }
    callback(null, {
      origin: true,
      allowedHeaders: Array.from(headers),
      exposedHeaders: ['Mcp-Session-Id']
    });
  };
  const corsMiddleware = cors(corsOptionsDelegate);

  const resolveMemoryKeyFromHeaders = (headers: Request['headers']): string | undefined => {
    if (config.storage === 'memory-single') return 'single';
    const keyName = storageHeaderKeyLower;
    if (!keyName) return undefined;
    const raw = headers[keyName];
    if (typeof raw === 'string') {
      const trimmed = raw.trim();
      return trimmed.length > 0 ? trimmed : undefined;
    }
    if (Array.isArray(raw)) {
      for (const value of raw) {
        if (typeof value === 'string') {
          const trimmed = value.trim();
          if (trimmed.length > 0) {
            return trimmed;
          }
        }
      }
    }
    return undefined;
  };

  const describeMemoryKey = (memoryKey: string) =>
    config.storage === 'memory-single' || !config.storageHeaderKey
      ? `"${memoryKey}"`
      : `${config.storageHeaderKey}="${memoryKey}"`;

  const toolsPrefix: string = argv.toolsPrefix;

  // stdio
  if (config.transport === 'stdio') {
    const memoryKey = "single";
    const server = createMcpServer(memoryKey, config, toolsPrefix);
    const transport = new StdioServerTransport();
    void server.connect(transport);
    console.log('Listening on stdio');
    return;
  }

  // Streamable HTTP (root "/")
  if (config.transport === 'http') {
    const httpMode = config.httpMode;
    const isStatefulHttp = httpMode === 'stateful';
    const app = express();

    app.use(corsMiddleware);
    app.options('*', corsMiddleware);

    if (isStatefulHttp) {
      app.use((req, res, next) => {
        if (req.path === '/') return next();
        return express.json()(req, res, next);
      });
    } else {
      app.use(express.json());
    }

    const createServerFor = (memoryKey: string) =>
      createMcpServer(memoryKey, config, toolsPrefix);

    if (isStatefulHttp) {
      interface HttpSession {
        memoryKey: string;
        server: McpServer;
        transport: StreamableHTTPServerTransport;
      }
      const sessions = new Map<string, HttpSession>();
      const eventStore = new InMemoryEventStore();

      app.post('/', async (req: Request, res: ExpressResponse) => {
        try {
          const sessionId = req.headers['mcp-session-id'] as string | undefined;

          if (sessionId && sessions.has(sessionId)) {
            const { transport } = sessions.get(sessionId)!;
            await transport.handleRequest(req, res);
            return;
          }

          const memoryKey = resolveMemoryKeyFromHeaders(req.headers);
          if (!memoryKey) {
            res.status(400).json({
              jsonrpc: '2.0',
              error: {
                code: -32000,
                message: config.storageHeaderKey
                  ? `Bad Request: Missing or invalid "${config.storageHeaderKey}" header`
                  : 'Bad Request: Missing required storage identifier'
              },
              id: (req as any)?.body?.id
            });
            return;
          }

          const server = createServerFor(memoryKey);

          let transport!: StreamableHTTPServerTransport;
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            eventStore,
            onsessioninitialized: (newSessionId: string) => {
              sessions.set(newSessionId, { memoryKey, server, transport });
              console.log(`[${newSessionId}] HTTP session initialized for ${describeMemoryKey(memoryKey)}`);
            }
          });

          transport.onclose = async () => {
            const sid = transport.sessionId;
            if (sid && sessions.has(sid)) {
              sessions.delete(sid);
              console.log(`[${sid}] Transport closed; removed session`);
            }
            try {
              await server.close();
            } catch {
              // already closed
            }
          };

          await server.connect(transport);
          await transport.handleRequest(req, res);
        } catch (err) {
          console.error('Error handling HTTP POST /:', err);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id
            });
          }
        }
      });

      app.get('/', async (req: Request, res: ExpressResponse) => {
        saveMachineId(req);
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !sessions.has(sessionId)) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
            id: (req as any)?.body?.id
          });
          return;
        }
        try {
          const { transport } = sessions.get(sessionId)!;
          await transport.handleRequest(req, res);
        } catch (err) {
          console.error(`[${sessionId}] Error handling HTTP GET /:`, err);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id
            });
          }
        }
      });

      app.delete('/', async (req: Request, res: ExpressResponse) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !sessions.has(sessionId)) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Bad Request: No valid session ID provided' },
            id: (req as any)?.body?.id
          });
          return;
        }
        try {
          const { transport } = sessions.get(sessionId)!;
          await transport.handleRequest(req, res);
        } catch (err) {
          console.error(`[${sessionId}] Error handling HTTP DELETE /:`, err);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Error handling session termination' },
              id: (req as any)?.body?.id
            });
          }
        }
      });
    } else {
      interface StatelessSession {
        memoryKey: string;
        server: McpServer;
        transport: StreamableHTTPServerTransport;
      }

      const statelessSessions = new Map<string, StatelessSession>();
      const statelessSessionPromises = new Map<string, Promise<StatelessSession>>();

      const destroyStatelessSession = async (memoryKey: string) => {
        const session = statelessSessions.get(memoryKey);
        if (!session) return;
        statelessSessions.delete(memoryKey);
        statelessSessionPromises.delete(memoryKey);
        try {
          await session.transport.close();
        } catch (err) {
          console.error(`[stateless:${memoryKey}] Error closing transport:`, err);
        }
        try {
          await session.server.close();
        } catch (err) {
          console.error(`[stateless:${memoryKey}] Error closing server:`, err);
        }
      };

      const getOrCreateStatelessSession = async (memoryKey: string): Promise<StatelessSession> => {
        const existing = statelessSessions.get(memoryKey);
        if (existing) {
          return existing;
        }

        const pending = statelessSessionPromises.get(memoryKey);
        if (pending) {
          return pending;
        }

        const creation = (async () => {
          const server = createServerFor(memoryKey);
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined
          });
          transport.onerror = error => {
            console.error(`[stateless:${memoryKey}] Streamable HTTP transport error:`, error);
          };
          transport.onclose = async () => {
            statelessSessions.delete(memoryKey);
            statelessSessionPromises.delete(memoryKey);
            try {
              await server.close();
            } catch (err) {
              console.error(`[stateless:${memoryKey}] Error closing server on transport close:`, err);
            }
          };
          await server.connect(transport);
          const session: StatelessSession = { memoryKey, server, transport };
          statelessSessions.set(memoryKey, session);
          return session;
        })()
          .catch(err => {
            statelessSessionPromises.delete(memoryKey);
            throw err;
          })
          .finally(() => {
            statelessSessionPromises.delete(memoryKey);
          });

        statelessSessionPromises.set(memoryKey, creation);
        return creation;
      };

      const handleStatelessRequest = async (
        req: Request,
        res: ExpressResponse,
        handler: (session: StatelessSession, memoryKey: string) => Promise<void>
      ) => {
        saveMachineId(req);
        const memoryKey = resolveMemoryKeyFromHeaders(req.headers);
        if (!memoryKey) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: config.storageHeaderKey
                ? `Bad Request: Missing or invalid "${config.storageHeaderKey}" header`
                : 'Bad Request: Missing required storage identifier'
            },
            id: (req as any)?.body?.id ?? null
          });
          return;
        }

        try {
          const session = await getOrCreateStatelessSession(memoryKey);
          await handler(session, memoryKey);
        } catch (err) {
          console.error('Error handling HTTP request (stateless):', err);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: { code: -32603, message: 'Internal server error' },
              id: (req as any)?.body?.id ?? null
            });
          }
        }
      };

      app.post('/', async (req: Request, res: ExpressResponse) => {
        await handleStatelessRequest(req, res, async ({ transport }, memoryKey) => {
          res.on('close', () => {
            if (!res.writableEnded) {
              console.error(`[stateless:${memoryKey}] POST connection closed prematurely; destroying session`);
              void destroyStatelessSession(memoryKey);
            }
          });

          await transport.handleRequest(req, res, req.body);
        });
      });

      app.get('/', async (req: Request, res: ExpressResponse) => {
        await handleStatelessRequest(req, res, async ({ transport }) => {
          await transport.handleRequest(req, res);
        });
      });

      app.delete('/', async (req: Request, res: ExpressResponse) => {
        await handleStatelessRequest(req, res, async ({ transport }, memoryKey) => {
          try {
            await transport.handleRequest(req, res);
          } finally {
            void destroyStatelessSession(memoryKey);
          }
        });
      });
    }

    app.listen(config.port, () => {
      console.log(`Listening on port ${config.port} (http:${httpMode})`);
    });

    return; // do not fall through to SSE
  }

  // SSE
  const app = express();
  interface ServerSession {
    memoryKey: string;
    server: McpServer;
    transport: SSEServerTransport;
    sessionId: string;
  }
  let sessions: ServerSession[] = [];

  app.use(corsMiddleware);
  app.options('*', corsMiddleware);

  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: ExpressResponse) => {
    saveMachineId(req);
    const memoryKey = resolveMemoryKeyFromHeaders(req.headers);
    if (!memoryKey) {
      const message = config.storageHeaderKey
        ? `Missing or invalid "${config.storageHeaderKey}" header`
        : 'Missing required storage identifier';
      res.status(400).json({ error: message });
      return;
    }
    const server = createMcpServer(memoryKey, config, toolsPrefix);
    const transport = new SSEServerTransport('/message', res);
    await server.connect(transport);
    const sessionId = transport.sessionId;
    sessions.push({ memoryKey, server, transport, sessionId });
    console.log(`[${sessionId}] SSE connected for ${describeMemoryKey(memoryKey)}`);
    transport.onclose = () => {
      console.log(`[${sessionId}] SSE connection closed`);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    transport.onerror = (err: Error) => {
      console.error(`[${sessionId}] SSE error:`, err);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    req.on('close', () => {
      console.log(`[${sessionId}] Client disconnected`);
      sessions = sessions.filter(s => s.transport !== transport);
    });
  });

  app.post('/message', async (req: Request, res: ExpressResponse) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      console.error('Missing sessionId');
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.sessionId === sessionId);
    if (!target) {
      console.error(`No active session for sessionId=${sessionId}`);
      res.status(404).send({ error: 'No active session' });
      return;
    }
    try {
      await target.transport.handlePostMessage(req, res);
    } catch (err: any) {
      console.error(`[${sessionId}] Error handling /message:`, err);
      res.status(500).send({ error: 'Internal error' });
    }
  });

  app.listen(config.port, () => {
    const headerInfo =
      config.storage === 'memory-single'
        ? 'memory-single mode'
        : `header "${config.storageHeaderKey}"`;
    console.log(`Listening on port ${config.port} (sse) using ${headerInfo}`);
  });
}

main().catch((err: any) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
