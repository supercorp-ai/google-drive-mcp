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
// 1) Parse CLI options (client credentials are now passed via CLI)
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
// 2) Setup scopes, OAuth2 Client, and Drive client
// --------------------------------------------------------------------
const SCOPES = ['https://www.googleapis.com/auth/drive.file']

const CLIENT_ID = argv.clientId || process.env.GOOGLE_CLIENT_ID || ''
const CLIENT_SECRET = argv.clientSecret || process.env.GOOGLE_CLIENT_SECRET || ''
const REDIRECT_URI = argv.redirectUri || process.env.GOOGLE_REDIRECT_URI || ''

const oauth2Client = new OAuth2Client(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI)
// No token is set initially; the client must supply it via save_token.

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

async function getFile(fileId: string): Promise<drive_v3.Schema$File | { error: string }> {
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

// --------------------------------------------------------------------
// 5) MCP Server: Tools for Saving Token & Interacting with Drive
// --------------------------------------------------------------------
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: 'Google Drive MCP Server',
    version: '1.0.0'
  })

  // Tool to save an access token provided by the client (e.g., from Google Picker)
  server.tool(
    'save_token',
    'Save an access token from the client for Google Drive access',
    { token: z.string() },
    async ({ token }, extra) => {
      try {
        oauth2Client.setCredentials({ access_token: token })
        log('Access token saved.')
        return wrapResponse({ success: true })
      } catch (err: any) {
        logErr('Failed to save token:', err)
        return wrapResponse({ error: String(err.message) })
      }
    }
  )

  // Tool to list files in Google Drive
  server.tool(
    'list_files',
    'List files in Google Drive',
    { pageSize: z.number().optional(), query: z.string().optional() },
    async (args, extra) => {
      const result = await listFiles(args)
      return wrapResponse(result)
    }
  )

  // Tool to get metadata for a specific file
  server.tool(
    'get_file',
    'Get metadata for a specific file',
    { fileId: z.string() },
    async ({ fileId }, extra) => {
      const result = await getFile(fileId)
      return wrapResponse(result)
    }
  )

  // Additional tools (e.g. upload, update, delete) can be added here.

  return server
}

// --------------------------------------------------------------------
// 6) Express Server & MCP Transport Setup
// --------------------------------------------------------------------
function main() {
  const server = createMcpServer()

  if (argv.transport === 'stdio') {
    const transport = new StdioServerTransport()
    void server.connect(transport)
    log('Listening on stdio')
    return
  }

  const port = argv.port
  const app = express()
  let sessions: { server: McpServer; transport: SSEServerTransport }[] = []

  app.use((req, res, next) => {
    if (req.path === '/message') return next()
    express.json()(req, res, next)
  })

  app.get('/', async (req: Request, res: Response) => {
    const transport = new SSEServerTransport('/message', res)
    const mcpInstance = createMcpServer()
    await mcpInstance.connect(transport)
    sessions.push({ server: mcpInstance, transport })

    const sessionId = transport.sessionId
    log(`[${sessionId}] SSE connection established`)

    transport.onclose = () => {
      log(`[${sessionId}] SSE closed`)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    transport.onerror = (err: Error) => {
      logErr(`[${sessionId}] SSE error:`, err)
      sessions = sessions.filter(s => s.transport !== transport)
    }
    req.on('close', () => {
      log(`[${sessionId}] SSE client disconnected`)
      sessions = sessions.filter(s => s.transport !== transport)
    })
  })

  app.post('/message', async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string
    if (!sessionId) {
      logErr('Missing sessionId')
      res.status(400).send({ error: 'Missing sessionId' })
      return
    }
    const target = sessions.find(s => s.transport.sessionId === sessionId)
    if (!target) {
      logErr(`No active session for sessionId=${sessionId}`)
      res.status(404).send({ error: 'No active session' })
      return
    }
    try {
      await target.transport.handlePostMessage(req, res)
    } catch (err: any) {
      logErr(`[${sessionId}] Error handling /message:`, err)
      res.status(500).send({ error: 'Internal error' })
    }
  })

  app.listen(port, () => {
    log(`Listening on port ${port} (${argv.transport})`)
  })
}

main()
