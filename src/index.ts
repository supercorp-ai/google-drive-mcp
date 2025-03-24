#!/usr/bin/env node

import yargs from 'yargs'
import { hideBin } from 'yargs/helpers'
import express, { Request, Response } from 'express'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { google, drive_v3 } from 'googleapis'
import { OAuth2Client } from 'google-auth-library'

// --------------------------------------------------------------------
// 1) Parse CLI options (client credentials are passed via CLI only)
// --------------------------------------------------------------------
const argv = yargs(hideBin(process.argv))
  .option('port', { type: 'number', default: 8000 })
  .option('transport', { type: 'string', choices: ['sse', 'stdio'], default: 'sse' })
  .option('clientId', { type: 'string', demandOption: true, describe: 'Google Client ID' })
  .option('clientSecret', { type: 'string', demandOption: true, describe: 'Google Client Secret' })
  .option('redirectUri', { type: 'string', demandOption: true, describe: 'Google Redirect URI' })
  .help()
  .parseSync()

const log = (...args: any[]) => console.log('[google-drive-mcp]', ...args)
const logErr = (...args: any[]) => console.error('[google-drive-mcp]', ...args)

// --------------------------------------------------------------------
// 2) Setup OAuth2 Client and Drive client using CLI credentials
// --------------------------------------------------------------------
const CLIENT_ID = argv.clientId;
const CLIENT_SECRET = argv.clientSecret;
const REDIRECT_URI = argv.redirectUri;

const oauth2Client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)
// No token is set initially; the client must supply it via the save_token tool.

const drive = google.drive({ version: 'v3', auth: oauth2Client })

// --------------------------------------------------------------------
// 3) Helper: Wrap responses in required MCP format
// --------------------------------------------------------------------
function wrapResponse(data: any): { content: { type: 'text'; text: string }[] } {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] }
}

// --------------------------------------------------------------------
// 4) Helper Functions for Drive Operations
// --------------------------------------------------------------------
async function listFiles(args: { pageSize?: number; query?: string } = {}): Promise<{ nextPageToken?: string | null; files?: drive_v3.Schema$File[] } | { error: string }> {
  try {
    const { pageSize = 10, query = '' } = args
    const res = await drive.files.list({
      pageSize,
      q: query,
      fields: 'nextPageToken, files(id, name, mimeType, modifiedTime)'
    })
    return { nextPageToken: res.data.nextPageToken, files: res.data.files }
  } catch (err: any) {
    return { error: String(err.message) }
  }
}

async function getFileMetadata(fileId: string): Promise<drive_v3.Schema$File | { error: string }> {
  try {
    const res = await drive.files.get({
      fileId,
      fields: 'id, name, mimeType, modifiedTime, webViewLink'
    })
    return res.data
  } catch (err: any) {
    return { error: String(err.message) }
  }
}

// Read file content with export for Docs Editors files
async function readFile(fileId: string, exportMimeType?: string): Promise<{ content?: string } | { error: string }> {
  try {
    const meta = await drive.files.get({
      fileId,
      fields: 'mimeType'
    });
    const fileMimeType = meta.data.mimeType;
    const exportMimeMap: { [key: string]: string } = {
      'application/vnd.google-apps.document': 'text/plain',         // Google Docs as plain text
      'application/vnd.google-apps.spreadsheet': 'text/csv',          // Google Sheets as CSV
      'application/vnd.google-apps.presentation': 'application/pdf'   // Google Slides as PDF
    };

    if (fileMimeType && exportMimeMap[fileMimeType]) {
      const mimeToUse = exportMimeType || exportMimeMap[fileMimeType];
      const res = await drive.files.export(
        { fileId, mimeType: mimeToUse },
        { responseType: 'text' }
      );
      return { content: res.data as string };
    } else {
      const res = await drive.files.get(
        { fileId, alt: 'media' },
        { responseType: 'text' }
      );
      return { content: res.data as string };
    }
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

async function moveFile(fileId: string, newFolderId: string): Promise<{ id?: string; parents?: string[] } | { error: string }> {
  try {
    // Get current parents
    const file = await drive.files.get({
      fileId,
      fields: 'parents'
    });
    const previousParents = file.data.parents?.join(',') || '';

    // Update the file's parents: add the new folder and remove the existing ones.
    const res = await drive.files.update({
      fileId,
      addParents: newFolderId,
      removeParents: previousParents,
      fields: 'id, parents'
    });

    // Return only the properties we need.
    return {
      id: res.data.id === null ? undefined : res.data.id,
      parents: res.data.parents ?? undefined
    };
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

// New helper: Create a file
async function createFile(args: { name: string; mimeType?: string; content: string }): Promise<drive_v3.Schema$File | { error: string }> {
  try {
    const res = await drive.files.create({
      requestBody: {
        name: args.name,
        mimeType: args.mimeType || 'text/plain'
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

// New helper: Update a file
async function updateFile(args: { fileId: string; name?: string; mimeType?: string; content: string }): Promise<drive_v3.Schema$File | { error: string }> {
  try {
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

// New helper: Delete a file
async function deleteFile(fileId: string): Promise<{ success: boolean } | { error: string }> {
  try {
    await drive.files.delete({ fileId });
    return { success: true };
  } catch (err: any) {
    return { error: String(err.message) };
  }
}

// --------------------------------------------------------------------
// 5) MCP Server: Tools for Saving Token & Interacting with Drive
// --------------------------------------------------------------------
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'Google Drive MCP Server',
    version: '1.0.0'
  });

  // Tool to save an access token provided by the client (from Google Picker)
  server.tool(
    'save_token',
    'Save an access token from the client for Google Drive access',
    { token: z.string() },
    async ({ token }, extra) => {
      try {
        oauth2Client.setCredentials({ access_token: token });
        log('Access token saved.');
        return wrapResponse({ success: true });
      } catch (err: any) {
        logErr('Failed to save token:', err);
        return wrapResponse({ error: String(err.message) });
      }
    }
  );

  // Tool to list files in Google Drive
  server.tool(
    'list_files',
    'List files in Google Drive',
    { pageSize: z.number().optional(), query: z.string().optional() },
    async (args, extra) => {
      const result = await listFiles(args);
      return wrapResponse(result);
    }
  );

  // Tool to get file metadata (renamed from get_file)
  server.tool(
    'get_file_metadata',
    'Get metadata for a specific file',
    { fileId: z.string() },
    async ({ fileId }, extra) => {
      const result = await getFileMetadata(fileId);
      return wrapResponse(result);
    }
  );

  // Tool to read file content
  server.tool(
    'read_file',
    'Read file content from Google Drive',
    { fileId: z.string() },
    async ({ fileId }, extra) => {
      const result = await readFile(fileId);
      return wrapResponse(result);
    }
  );

  // Tool to create a new file
  server.tool(
    'create_file',
    'Create a new file on Google Drive',
    { name: z.string(), mimeType: z.string().optional(), content: z.string() },
    async (args, extra) => {
      const result = await createFile(args);
      return wrapResponse(result);
    }
  );

  // Tool to update an existing file
  server.tool(
    'update_file',
    'Update an existing file on Google Drive',
    { fileId: z.string(), name: z.string().optional(), mimeType: z.string().optional(), content: z.string() },
    async (args, extra) => {
      const result = await updateFile(args);
      return wrapResponse(result);
    }
  );

  // Tool to delete a file
  server.tool(
    'delete_file',
    'Delete a file from Google Drive',
    { fileId: z.string() },
    async ({ fileId }, extra) => {
      const result = await deleteFile(fileId);
      return wrapResponse(result);
    }
  );

  // New tool to move a file to a new folder
  server.tool(
    'move_file',
    'Move a file to a new folder on Google Drive',
    { fileId: z.string(), newFolderId: z.string() },
    async ({ fileId, newFolderId }, extra) => {
      const result = await moveFile(fileId, newFolderId);
      return wrapResponse(result);
    }
  );

  // Additional tools (e.g., copying, permission management) can be added here.

  return server;
}

// --------------------------------------------------------------------
// 6) Express Server & MCP Transport Setup
// --------------------------------------------------------------------
function main() {
  const server = createMcpServer();

  if (argv.transport === 'stdio') {
    const transport = new StdioServerTransport();
    void server.connect(transport);
    log('Listening on stdio');
    return;
  }

  const port = argv.port;
  const app = express();
  let sessions: { server: McpServer; transport: SSEServerTransport }[] = [];

  app.use((req, res, next) => {
    if (req.path === '/message') return next();
    express.json()(req, res, next);
  });

  app.get('/', async (req: Request, res: Response) => {
    const transport = new SSEServerTransport('/message', res);
    const mcpInstance = createMcpServer();
    await mcpInstance.connect(transport);
    sessions.push({ server: mcpInstance, transport });

    const sessionId = transport.sessionId;
    log(`[${sessionId}] SSE connection established`);

    transport.onclose = () => {
      log(`[${sessionId}] SSE closed`);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err);
      sessions = sessions.filter(s => s.transport !== transport);
    };
    req.on('close', () => {
      log(`[${sessionId}] SSE client disconnected`);
      sessions = sessions.filter(s => s.transport !== transport);
    });
  });

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId) {
      logErr('Missing sessionId');
      res.status(400).send({ error: 'Missing sessionId' });
      return;
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId);
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`);
      res.status(404).send({ error: 'No active session' });
      return;
    }
    try {
      await target.transport.handlePostMessage(req, res);
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err);
      res.status(500).send({ error: 'Internal error' });
    }
  });

  app.listen(port, () => {
    log(`Listening on port ${port} (${argv.transport})`);
  });
}

main();
