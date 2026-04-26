const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

const CONFIG = {
    PORT: process.env.PORT || 8080,
    HOST: process.env.HOST || '0.0.0.0',
    PUBLIC_DIR: process.env.PUBLIC_DIR || path.join(__dirname, 'public'),
    INDEX_FILE: 'index.html',
    NOT_FOUND_FILE: '404.html',
    ENABLE_HTTPS: process.env.ENABLE_HTTPS === 'true',
    SSL_KEY: process.env.SSL_KEY || path.join(__dirname, 'ssl', 'key.pem'),
    SSL_CERT: process.env.SSL_CERT || path.join(__dirname, 'ssl', 'cert.pem'),
    ENABLE_GZIP: process.env.ENABLE_GZIP !== 'false',
    ENABLE_CORS: process.env.ENABLE_CORS === 'true',
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 60000,
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    NODE_ENV: process.env.NODE_ENV || 'production'
};

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
    '.otf': 'font/otf',
    '.pdf': 'application/pdf',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.wasm': 'application/wasm'
};

const SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';"
};

const requestCounts = new Map();

function isRateLimited(clientIp) {
    const now = Date.now();
    const windowStart = now - CONFIG.RATE_LIMIT_WINDOW;
    if (!requestCounts.has(clientIp)) requestCounts.set(clientIp, []);
    const timestamps = requestCounts.get(clientIp).filter(t => t > windowStart);
    timestamps.push(now);
    requestCounts.set(clientIp, timestamps);
    return timestamps.length > CONFIG.RATE_LIMIT_MAX;
}

setInterval(() => {
    const now = Date.now();
    const windowStart = now - CONFIG.RATE_LIMIT_WINDOW;
    for (const [ip, timestamps] of requestCounts) {
        const filtered = timestamps.filter(t => t > windowStart);
        if (filtered.length === 0) requestCounts.delete(ip);
        else requestCounts.set(ip, filtered);
    }
}, 300000);

function getClientIp(req) {
    if (CONFIG.TRUST_PROXY) {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
}

function logRequest(req, statusCode, duration, bytes) {
    const timestamp = new Date().toISOString();
    const clientIp = getClientIp(req);
    console.log(`[${timestamp}] ${clientIp} - ${req.method} ${req.url} ${statusCode} ${bytes}B ${duration}ms`);
}

function getMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return MIME_TYPES[ext] || 'application/octet-stream';
}

function sanitizePath(requestPath) {
    const decoded = decodeURIComponent(requestPath);
    const normalized = path.normalize(decoded);
    if (normalized.startsWith('..') || normalized.includes('\x00')) return null;
    return normalized;
}

function sendError(statusCode, req, res, startTime) {
    const body = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${statusCode}</title></head><body><h1>${statusCode}</h1><p>${require('http').STATUS_CODES[statusCode]}</p></body></html>`;
    const headers = {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': Buffer.byteLength(body)
    };
    res.writeHead(statusCode, headers);
    res.end(body);
    logRequest(req, statusCode, Date.now() - startTime, Buffer.byteLength(body));
}

function serveFile(filePath, req, res, startTime) {
    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            sendError(404, req, res, startTime);
            return;
        }
        const mimeType = getMimeType(filePath);
        const headers = {
            'Content-Type': mimeType,
            'Cache-Control': mimeType.startsWith('text/html') ? 'no-cache, no-store, must-revalidate' : 'public, max-age=31536000, immutable',
            'ETag': `"${stats.mtime.getTime().toString(16)}-${stats.size.toString(16)}"`,
            'Last-Modified': stats.mtime.toUTCString()
        };
        const ifNoneMatch = req.headers['if-none-match'];
        const ifModifiedSince = req.headers['if-modified-since'];
        if ((ifNoneMatch && ifNoneMatch === headers['ETag']) || (ifModifiedSince && new Date(ifModifiedSince) >= stats.mtime)) {
            res.writeHead(304, headers);
            res.end();
            logRequest(req, 304, Date.now() - startTime, 0);
            return;
        }
        headers['Content-Length'] = stats.size;
        res.writeHead(200, headers);
        const stream = fs.createReadStream(filePath);
        let bytesSent = 0;
        stream.on('data', chunk => bytesSent += chunk.length);
        stream.pipe(res);
        res.on('finish', () => logRequest(req, 200, Date.now() - startTime, bytesSent));
    });
}

function handleRequest(req, res) {
    const startTime = Date.now();
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { 'Allow': 'GET, HEAD' });
        res.end();
        logRequest(req, 405, Date.now() - startTime, 0);
        return;
    }
    Object.entries(SECURITY_HEADERS).forEach(([key, value]) => res.setHeader(key, value));
    if (CONFIG.ENABLE_CORS) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD');
    }
    const clientIp = getClientIp(req);
    if (isRateLimited(clientIp)) {
        res.writeHead(429, { 'Content-Type': 'text/plain' });
        res.end('Too Many Requests');
        logRequest(req, 429, Date.now() - startTime, 19);
        return;
    }
    const parsedUrl = url.parse(req.url);
    let pathname = sanitizePath(parsedUrl.pathname);
    if (pathname === null) {
        sendError(403, req, res, startTime);
        return;
    }
    let filePath = path.join(CONFIG.PUBLIC_DIR, pathname);
    if (pathname.endsWith('/')) {
        filePath = path.join(filePath, CONFIG.INDEX_FILE);
    } else {
        try {
            const stats = fs.statSync(filePath);
            if (stats.isDirectory()) {
                res.writeHead(301, { 'Location': pathname + '/' });
                res.end();
                logRequest(req, 301, Date.now() - startTime, 0);
                return;
            }
        } catch (e) {}
    }
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            const htmlPath = filePath + '.html';
            fs.access(htmlPath, fs.constants.F_OK, (htmlErr) => {
                if (!htmlErr) serveFile(htmlPath, req, res, startTime);
                else sendError(404, req, res, startTime);
            });
            return;
        }
        serveFile(filePath, req, res, startTime);
    });
}

const server = http.createServer(handleRequest);

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`Port ${CONFIG.PORT} is already in use`);
        process.exit(1);
    }
    console.error('Server error:', err);
});

server.on('listening', () => {
    const addr = server.address();
    console.log(`Server running at http://${addr.address}:${addr.port}`);
    console.log(`Serving: ${path.resolve(CONFIG.PUBLIC_DIR)}`);
    console.log(`Environment: ${CONFIG.NODE_ENV}`);
    console.log('Press Ctrl+C to stop');
});

function shutdown(signal) {
    console.log(`\\n${signal} received. Shutting down gracefully...`);
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
    setTimeout(() => {
        console.error('Forced shutdown');
        process.exit(1);
    }, 10000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

server.listen(CONFIG.PORT, CONFIG.HOST);
