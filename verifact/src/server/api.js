'use strict';
// SPDX-License-Identifier: Apache-2.0

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { loadConfig } = require('../config');
const engine = require('../engine');
const { readRuns } = require('../history');
const { VerifactError } = require('../errors');

/**
 * 本地看板 + API。零依赖 node:http。
 * 只监听 127.0.0.1：这是读本机全盘路径的服务，不对外。
 */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

let LAST_REPORT = null;
let RUNNING = false;

function json(res, code, body) {
  const payload = JSON.stringify(body);
  res.writeHead(code, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(payload);
}

function readBody(req, limitBytes) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) { reject(new VerifactError('payload_too_large', 'body exceeds limit')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function serveStatic(res, rootDir, relPath) {
  const safe = path.normalize(relPath).replace(/^(\.\.[/\\])+/, '');
  const full = path.join(rootDir, safe);
  if (!full.startsWith(path.resolve(rootDir))) { res.writeHead(403); res.end('forbidden'); return; }
  if (!fs.existsSync(full) || !fs.statSync(full).isFile()) { res.writeHead(404); res.end('not found'); return; }
  const body = fs.readFileSync(full);
  res.writeHead(200, {
    'content-type': MIME[path.extname(full).toLowerCase()] || 'application/octet-stream',
    'content-length': body.length,
    'x-content-type-options': 'nosniff'
  });
  res.end(body);
}

function createServer(cfg, log) {
  const wwwDir = path.join(__dirname, 'www');

  return http.createServer(async (req, res) => {
    const started = Date.now();
    const parsed = url.parse(req.url, true);
    const route = parsed.pathname.replace(/\/+$/, '') || '/';

    try {
      // 健康检查
      if (route === '/api/health') {
        return json(res, 200, {
          status: 'ok',
          busy: RUNNING === true,
          hasReport: !!LAST_REPORT,
          configFile: cfg.__configFile,
          runs: readRuns(cfg, cfg.__cwd, 1).length
        });
      }

      if (route === '/api/config') {
        return json(res, 200, {
          docsRoots: cfg.docs.roots,
          artifactRoots: cfg.artifacts.roots,
          minScore: cfg.resolve.minScore,
          failOn: cfg.gate.failOn,
          modules: cfg.modules,
          cacheEnabled: cfg.cache.enabled,
          cwd: cfg.__cwd
        });
      }

      if (route === '/api/report' && req.method === 'GET') {
        if (!LAST_REPORT) {
          if (RUNNING) return json(res, 202, { pending: true, message: '一审还在跑' });
          LAST_REPORT = await engine.run(cfg, { logger: log });
        }
        return json(res, 200, LAST_REPORT);
      }

      if (route === '/api/verify' && req.method === 'POST') {
        if (RUNNING) return json(res, 409, { error: 'busy', message: '上一次核验仍在进行' });
        RUNNING = true;
        const t0 = Date.now();
        try {
          let opts = {};
          const raw = await readBody(req, 64 * 1024);
          if (raw) { try { opts = JSON.parse(raw) || {}; } catch (_) { /* 空 body 合法 */ } }
          const report = await engine.run(cfg, {
            deep: !!opts.deep,
            noCache: !!opts.noCache,
            concurrency: opts.concurrency,
            logger: log
          });
          LAST_REPORT = report;
          log.info('verify_done', { ms: Date.now() - t0, claims: report.counts.claims, drift: report.counts.drift });
          return json(res, 200, report);
        } finally {
          RUNNING = false;
        }
      }

      if (route === '/api/history') {
        const limit = Math.min(200, Number(parsed.query.limit) || 30);
        return json(res, 200, { runs: readRuns(cfg, cfg.__cwd, limit) });
      }

      if (route === '/' || route === '') {
        return serveStatic(res, wwwDir, 'index.html');
      }
      if (route.startsWith('/assets/')) {
        return serveStatic(res, wwwDir, route.slice('/assets/'.length));
      }
      if (route === '/app.js') return serveStatic(res, wwwDir, 'app.js');
      if (route === '/style.css') return serveStatic(res, wwwDir, 'style.css');

      return json(res, 404, { error: 'not_found', message: route });
    } catch (e) {
      if (e instanceof VerifactError) return json(res, e.code === 'payload_too_large' ? 413 : 400, e.toJSON());
      log.error('request_failed', { route, ms: Date.now() - started, message: e && e.message });
      return json(res, 500, { error: 'internal_error', message: '内部错误，详情见服务端日志' });
    }
  });
}

function start(cfg, log) {
  return new Promise((resolve, reject) => {
    const server = createServer(cfg, log || require('../logger').create({ quiet: true }));
    server.on('error', reject);
    server.listen(cfg.server.port, cfg.server.host, () => {
      const addr = server.address();
      log.info('server_listening', { host: cfg.server.host, port: addr.port });
      process.stdout.write('verifact dashboard → http://' + cfg.server.host + ':' + addr.port + '\n');
      resolve(server);
    });
  });
}

module.exports = { start, createServer, loadConfig };
