const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

// ─── Configuration ──────────────────────────────────────────────────────────
const CONFIG = {
    PORT: process.env.PORT || 8080,
    HTTPS_PORT: process.env.HTTPS_PORT || 8443,
    HOST: process.env.HOST || '0.0.0.0',
    PUBLIC_DIR: process.env.PUBLIC_DIR || path.join(__dirname, 'public'),
    INDEX_FILE: 'index.html',
    NOT_FOUND_FILE: '404.html',
    ENABLE_HTTPS: process.env.ENABLE_HTTPS === 'true',
    SSL_KEY: process.env.SSL_KEY || path.join(__dirname, 'ssl', 'key.pem'),
    SSL_CERT: process.env.SSL_CERT || path.join(__dirname, 'ssl', 'cert.pem'),
    ENABLE_GZIP: process.env.ENABLE_GZIP !== 'false',
    ENABLE_CORS: process.env.ENABLE_CORS === 'true',
    TRUST_PROXY: process.env.TRUST_PROXY === 'true',
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW) || 60000,
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    NODE_ENV: process.env.NODE_ENV || 'production'
};

// ─── MIME Types ───────────────────────────────────────────────────────────────
const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.htm': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.xml': 'application/xml; charset=utf-8',
    '.txt': 'text/plain; charset=utf-8',
    '.md': 'text/markdown; charset=utf-8',
    '.ico': 'image/x-icon',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.webp': 'image/webp',
    '.avif': 'image/avif',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
    '.otf': 'font/otf',
    '.eot': 'application/vnd.ms-fontobject',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.gz': 'application/gzip',
    '.tar': 'application/x-tar',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.mp3': 'audio/mpeg',
    '.ogg': 'audio/ogg',
    '.wav': 'audio/wav',
    '.wasm': 'application/wasm',
    '.map': 'application/json'
};

const COMPRESSIBLE_TYPES = [
    'text/', 'application/javascript', 'application/json',
    'application/xml', 'application/wasm'
];

// ─── Security Headers ─────────────────────────────────────────────────────────
const SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; media-src 'self' https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
};

// ─── Rate Limiting (Simple In-Memory) ─────────────────────────────────────────
const requestCounts = new Map();

function isRateLimited(clientIp) {
    const now = Date.now();
    const windowStart = now - CONFIG.RATE_LIMIT_WINDOW;

    if (!requestCounts.has(clientIp)) {
        requestCounts.set(clientIp, []);
    }

    const timestamps = requestCounts.get(clientIp).filter(t => t > windowStart);
    timestamps.push(now);
    requestCounts.set(clientIp, timestamps);

    return timestamps.length > CONFIG.RATE_LIMIT_MAX;
}

// Cleanup old entries every 5 minutes
setInterval(() => {
    const now = Date.now();
    const windowStart = now - CONFIG.RATE_LIMIT_WINDOW;
    for (const [ip, timestamps] of requestCounts) {
        const filtered = timestamps.filter(t => t > windowStart);
        if (filtered.length === 0) {
            requestCounts.delete(ip);
        } else {
            requestCounts.set(ip, filtered);
        }
    }
}, 300000);

// ─── Logging ──────────────────────────────────────────────────────────────────
function logRequest(req, statusCode, duration, bytes) {
    const timestamp = new Date().toISOString();
    const clientIp = getClientIp(req);
    const method = req.method;
    const url = req.url;
    const userAgent = req.headers['user-agent'] || '-';

    console.log(`[${timestamp}] ${clientIp} - ${method} ${url} ${statusCode} ${bytes}B ${duration}ms - ${userAgent}`);
}

function getClientIp(req) {
    if (CONFIG.TRUST_PROXY) {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
}

// ─── File Serving ─────────────────────────────────────────────────────────────
function getMimeType(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    return MIME_TYPES[ext] || 'application/octet-stream';
}

function isCompressible(mimeType) {
    return COMPRESSIBLE_TYPES.some(type => mimeType.startsWith(type));
}

function sanitizePath(requestPath) {
    // Prevent directory traversal
    const decoded = decodeURIComponent(requestPath);
    const normalized = path.normalize(decoded);

    if (normalized.startsWith('..') || normalized.includes('\x00')) {
        return null;
    }

    return normalized;
}

function serveFile(filePath, req, res) {
    const startTime = Date.now();

    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            sendError(404, req, res, startTime);
            return;
        }

        const mimeType = getMimeType(filePath);
        const headers = {
            'Content-Type': mimeType,
            'Cache-Control': mimeType.startsWith('text/html') 
                ? 'no-cache, no-store, must-revalidate'
                : 'public, max-age=31536000, immutable',
            'ETag': `"${stats.mtime.getTime().toString(16)}-${stats.size.toString(16)}"`,
            'Last-Modified': stats.mtime.toUTCString()
        };

        // Handle If-None-Match / If-Modified-Since
        const ifNoneMatch = req.headers['if-none-match'];
        const ifModifiedSince = req.headers['if-modified-since'];

        if ((ifNoneMatch && ifNoneMatch === headers['ETag']) ||
            (ifModifiedSince && new Date(ifModifiedSince) >= stats.mtime)) {
            res.writeHead(304, headers);
            res.end();
            logRequest(req, 304, Date.now() - startTime, 0);
            return;
        }

        // Check for gzip support
        const acceptEncoding = req.headers['accept-encoding'] || '';
        const supportsGzip = acceptEncoding.includes('gzip') && isCompressible(mimeType) && CONFIG.ENABLE_GZIP;

        if (supportsGzip && stats.size > 1024) {
            const zlib = require('zlib');
            headers['Content-Encoding'] = 'gzip';
            delete headers['Content-Length'];

            res.writeHead(200, headers);

            const stream = fs.createReadStream(filePath);
            const gzip = zlib.createGzip({ level: 6 });

            let bytesSent = 0;
            stream.on('data', chunk => bytesSent += chunk.length);

            stream.pipe(gzip).pipe(res);

            res.on('finish', () => {
                logRequest(req, 200, Date.now() - startTime, bytesSent);
            });
        } else {
            headers['Content-Length'] = stats.size;
            res.writeHead(200, headers);

            const stream = fs.createReadStream(filePath);
            let bytesSent = 0;

            stream.on('data', chunk => bytesSent += chunk.length);
            stream.pipe(res);

            res.on('finish', () => {
                logRequest(req, 200, Date.now() - startTime, bytesSent);
            });
        }
    });
}

function sendError(statusCode, req, res, startTime = Date.now()) {
    const errorFile = path.join(CONFIG.PUBLIC_DIR, CONFIG.NOT_FOUND_FILE);

    const sendSimpleError = () => {
        const body = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>${statusCode}</title></head>
<body><h1>${statusCode}</h1><p>${http.STATUS_CODES[statusCode]}</p></body>
</html>`;

        const headers = {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Length': Buffer.byteLength(body)
        };

        res.writeHead(statusCode, headers);
        res.end(body);
        logRequest(req, statusCode, Date.now() - startTime, Buffer.byteLength(body));
    };

    if (statusCode === 404 && fs.existsSync(errorFile)) {
        fs.readFile(errorFile, (err, data) => {
            if (err) {
                sendSimpleError();
                return;
            }
            const headers = {
                'Content-Type': 'text/html; charset=utf-8',
                'Content-Length': data.length,
                'Cache-Control': 'no-cache, no-store, must-revalidate'
            };
            res.writeHead(404, headers);
            res.end(data);
            logRequest(req, 404, Date.now() - startTime, data.length);
        });
    } else {
        sendSimpleError();
    }
}

// ─── Request Handler ──────────────────────────────────────────────────────────
function handleRequest(req, res) {
    const startTime = Date.now();

    // Only handle GET and HEAD
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, { 'Allow': 'GET, HEAD' });
        res.end();
        logRequest(req, 405, Date.now() - startTime, 0);
        return;
    }

    // Apply security headers
    Object.entries(SECURITY_HEADERS).forEach(([key, value]) => {
        res.setHeader(key, value);
    });

    // CORS if enabled
    if (CONFIG.ENABLE_CORS) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD');
    }

    // Rate limiting
    const clientIp = getClientIp(req);
    if (isRateLimited(clientIp)) {
        res.writeHead(429, { 'Content-Type': 'text/plain' });
        res.end('Too Many Requests');
        logRequest(req, 429, Date.now() - startTime, 19);
        return;
    }

    // Parse and sanitize URL
    const parsedUrl = url.parse(req.url);
    let pathname = sanitizePath(parsedUrl.pathname);

    if (pathname === null) {
        sendError(403, req, res, startTime);
        return;
    }

    // Resolve file path
    let filePath = path.join(CONFIG.PUBLIC_DIR, pathname);

    // If path is a directory, look for index.html
    if (pathname.endsWith('/')) {
        filePath = path.join(filePath, CONFIG.INDEX_FILE);
    } else {
        // Check if it's a directory without trailing slash
        try {
            const stats = fs.statSync(filePath);
            if (stats.isDirectory()) {
                res.writeHead(301, { 'Location': pathname + '/' });
                res.end();
                logRequest(req, 301, Date.now() - startTime, 0);
                return;
            }
        } catch (e) {
            // Not a directory, continue
        }
    }

    // Check if file exists
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            // Try adding .html extension (clean URLs)
            const htmlPath = filePath + '.html';
            fs.access(htmlPath, fs.constants.F_OK, (htmlErr) => {
                if (!htmlErr) {
                    serveFile(htmlPath, req, res);
                } else {
                    sendError(404, req, res, startTime);
                }
            });
            return;
        }

        serveFile(filePath, req, res);
    });
}

// ─── Server Creation ──────────────────────────────────────────────────────────
function createServer() {
    const server = http.createServer(handleRequest);

    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`❌ Port ${CONFIG.PORT} is already in use`);
            process.exit(1);
        }
        console.error('❌ Server error:', err);
    });

    server.on('listening', () => {
        const addr = server.address();
        console.log(`\n🚀 Server running at http://${addr.address}:${addr.port}`);
        console.log(`📁 Serving: ${path.resolve(CONFIG.PUBLIC_DIR)}`);
        console.log(`🌍 Environment: ${CONFIG.NODE_ENV}`);
        console.log(`⏱️  Rate limit: ${CONFIG.RATE_LIMIT_MAX} requests / ${CONFIG.RATE_LIMIT_WINDOW}ms`);
        console.log(`🗜️  Gzip: ${CONFIG.ENABLE_GZIP ? 'enabled' : 'disabled'}`);
        console.log(`🔒 HTTPS: ${CONFIG.ENABLE_HTTPS ? 'enabled' : 'disabled'}`);
        console.log('\nPress Ctrl+C to stop\n');
    });

    return server;
}

// ─── HTTPS Server (Optional) ──────────────────────────────────────────────────
function createHttpsServer() {
    if (!CONFIG.ENABLE_HTTPS) return null;

    try {
        const key = fs.readFileSync(CONFIG.SSL_KEY);
        const cert = fs.readFileSync(CONFIG.SSL_CERT);

        const server = https.createServer({ key, cert }, handleRequest);

        server.on('listening', () => {
            const addr = server.address();
            console.log(`🔒 HTTPS server running at https://${addr.address}:${addr.port}`);
        });

        return server;
    } catch (err) {
        console.error('❌ Failed to start HTTPS server:', err.message);
        return null;
    }
}

// ─── Graceful Shutdown ──────────────────────────────────────────────────────────
function setupGracefulShutdown(server, httpsServer = null) {
    const shutdown = (signal) => {
        console.log(`\n${signal} received. Shutting down gracefully...`);

        server.close(() => {
            console.log('✅ HTTP server closed');

            if (httpsServer) {
                httpsServer.close(() => {
                    console.log('✅ HTTPS server closed');
                    process.exit(0);
                });
            } else {
                process.exit(0);
            }
        });

        // Force shutdown after 10 seconds
        setTimeout(() => {
            console.error('⚠️  Forced shutdown');
            process.exit(1);
        }, 10000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

// ─── Start ────────────────────────────────────────────────────────────────────
const server = createServer();
server.listen(CONFIG.PORT, CONFIG.HOST);

const httpsServer = createHttpsServer();
if (httpsServer) {
    httpsServer.listen(CONFIG.HTTPS_PORT, CONFIG.HOST);
}

setupGracefulShutdown(server, httpsServer);

module.exports = { CONFIG, MIME_TYPES, SECURITY_HEADERS };
