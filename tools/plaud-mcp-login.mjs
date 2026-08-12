#!/usr/bin/env node
// plaud-mcp-login.mjs — mint a durable Plaud OAuth token via the OFFICIAL
// @plaud-ai/mcp server.
//
// Why this exists: in @plaud-ai/mcp, `login` is an MCP *tool*, not a CLI command
// — `npx @plaud-ai/mcp login` just starts the stdio server and appears to hang.
// This driver speaks MCP over stdio, calls the `login` tool (which opens your
// browser for Google sign-in and runs the OAuth callback on localhost:8199), and
// the server writes the token (~300-day, refreshing) to ~/.plaud/tokens-mcp.json.
//
// Then import it into m3c-tools:   ./build/m3c-tools plaud auth mcp
//
// Usage:  node tools/plaud-mcp-login.mjs
import { spawn } from 'node:child_process';

const srv = spawn('npx', ['-y', '@plaud-ai/mcp@latest'], { stdio: ['pipe', 'pipe', 'ignore'] });
const send = (o) => srv.stdin.write(JSON.stringify(o) + '\n');
let buf = '';

srv.stdout.on('data', (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let m;
    try { m = JSON.parse(line); } catch { continue; }

    if (m.id === 1) {
      // initialized → call the login tool
      send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      console.error('\n  A browser window will open for Plaud sign-in (Google/Apple SSO supported).');
      console.error('  Complete the sign-in, then return here — this finishes automatically.\n');
      send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'login', arguments: {} } });
    } else if (m.id === 2) {
      const text = m.result?.content?.map((c) => c.text).join(' ')
        ?? JSON.stringify(m.result ?? m.error);
      console.error('  [plaud-mcp] ' + text);
      console.error('\n  Now import it:  ./build/m3c-tools plaud auth mcp\n');
      srv.kill();
      process.exit(m.error ? 1 : 0);
    }
  }
});

srv.on('error', (e) => { console.error('  Could not start @plaud-ai/mcp:', e.message); process.exit(1); });

send({
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'm3c-tools', version: '1' } },
});

// The OAuth callback has a 120s server-side timeout; give it a little more.
setTimeout(() => { console.error('  Timed out waiting for sign-in.'); srv.kill(); process.exit(1); }, 140000);
