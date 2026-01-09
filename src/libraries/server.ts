/**
 * @author Eltik. Credit to CORS proxy by Rob Wu.
 * @description Proxies m3u8 files.
 * @license MIT
 */
import dotenv from "dotenv";
dotenv.config();
import httpProxy from "http-proxy";
import https from "node:https";
import http, { Server } from "node:http";
import net from "node:net";
import url from "node:url";
import { getProxyForUrl } from "proxy-from-env";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import colors from "colors";
import axios from "axios";
function withCORS(headers, request) {
    headers["access-control-allow-origin"] = "*";
    const corsMaxAge = request.corsAnywhereRequestState.corsMaxAge;
    if (request.method === "OPTIONS" && corsMaxAge) {
        headers["access-control-max-age"] = corsMaxAge;
    }
    if (request.headers["access-control-request-method"]) {
        headers["access-control-allow-methods"] = request.headers["access-control-request-method"];
        delete request.headers["access-control-request-method"];
    }
    if (request.headers["access-control-request-headers"]) {
        headers["access-control-allow-headers"] = request.headers["access-control-request-headers"];
        delete request.headers["access-control-request-headers"];
    }
    headers["access-control-expose-headers"] = Object.keys(headers).join(",");
    return headers;
}
function proxyRequest(req, res, proxy) {
    const location = req.corsAnywhereRequestState.location;
    req.url = location.path;
    const proxyOptions = {
        changeOrigin: false,
        prependPath: false,
        target: location,
        headers: {
            host: location.host,
        },
        // HACK: Get hold of the proxyReq object, because we need it later.
        // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L144
        buffer: {
            pipe: function (proxyReq) {
                const proxyReqOn = proxyReq.on;
                // Intercepts the handler that connects proxyRes to res.
                // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L146-L158
                proxyReq.on = function (eventName, listener) {
                    if (eventName !== "response") {
                        return proxyReqOn.call(this, eventName, listener);
                    }
                    return proxyReqOn.call(this, "response", function (proxyRes) {
                        if (onProxyResponse(proxy, proxyReq, proxyRes, req, res)) {
                            try {
                                listener(proxyRes);
                            } catch (err) {
                                // Wrap in try-catch because an error could occur:
                                // "RangeError: Invalid status code: 0"
                                // https://github.com/Rob--W/cors-anywhere/issues/95
                                // https://github.com/nodejitsu/node-http-proxy/issues/1080
                                // Forward error (will ultimately emit the 'error' event on our proxy object):
                                // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L134
                                proxyReq.emit("error", err);
                            }
                        }
                    });
                };
                return req.pipe(proxyReq);
            },
        },
    };
    const proxyThroughUrl = req.corsAnywhereRequestState.getProxyForUrl(location.href);
    if (proxyThroughUrl) {
        proxyOptions.target = proxyThroughUrl;
        (proxyOptions as any).toProxy = true;
        // If a proxy URL was set, req.url must be an absolute URL. Then the request will not be sent
        // directly to the proxied URL, but through another proxy.
        req.url = location.href;
    }
    // Start proxying the request
    try {
        proxy.web(req, res, proxyOptions);
    } catch (err) {
        console.error(err);
        console.log(proxy);
        //proxy.emit('error', err, req, res);
    }
}
function onProxyResponse(proxy, proxyReq, proxyRes, req, res) {
    const requestState = req.corsAnywhereRequestState;
    const statusCode = proxyRes.statusCode;
    if (!requestState.redirectCount_) {
        res.setHeader("x-request-url", requestState.location.href);
    }
    // Handle redirects
    if (statusCode === 301 || statusCode === 302 || statusCode === 303 || statusCode === 307 || statusCode === 308) {
        let locationHeader = proxyRes.headers.location;
        let parsedLocation;
        if (locationHeader) {
            locationHeader = url.resolve(requestState.location.href, locationHeader);
            parsedLocation = parseURL(locationHeader);
        }
        if (parsedLocation) {
            if (statusCode === 301 || statusCode === 302 || statusCode === 303) {
                // Exclude 307 & 308, because they are rare, and require preserving the method + request body
                requestState.redirectCount_ = requestState.redirectCount_ + 1 || 1;
                if (requestState.redirectCount_ <= requestState.maxRedirects) {
                    // Handle redirects within the server, because some clients (e.g. Android Stock Browser)
                    // cancel redirects.
                    // Set header for debugging purposes. Do not try to parse it!
                    res.setHeader("X-CORS-Redirect-" + requestState.redirectCount_, statusCode + " " + locationHeader);
                    req.method = "GET";
                    req.headers["content-length"] = "0";
                    delete req.headers["content-type"];
                    requestState.location = parsedLocation;
                    // Remove all listeners (=reset events to initial state)
                    req.removeAllListeners();
                    // Remove the error listener so that the ECONNRESET "error" that
                    // may occur after aborting a request does not propagate to res.
                    // https://github.com/nodejitsu/node-http-proxy/blob/v1.11.1/lib/http-proxy/passes/web-incoming.js#L134
                    proxyReq.removeAllListeners("error");
                    proxyReq.once("error", function catchAndIgnoreError() {});
                    proxyReq.abort();
                    // Initiate a new proxy request.
                    proxyRequest(req, res, proxy);
                    return false;
                }
            }
            proxyRes.headers.location = requestState.proxyBaseUrl + "/" + locationHeader;
        }
    }
    // Strip cookies
    delete proxyRes.headers["set-cookie"];
    delete proxyRes.headers["set-cookie2"];
    proxyRes.headers["x-final-url"] = requestState.location.href;
    withCORS(proxyRes.headers, req);
    return true;
}
function parseURL(req_url) {
    const match = req_url.match(/^(?:(https?:)?\/\/)?(([^\/?]+?)(?::(\d{0,5})(?=[\/?]|$))?)([\/?][\S\s]*|$)/i);
    // ^^^^^^^ ^^^^^^^^ ^^^^^^^ ^^^^^^^^^^^^
    // 1:protocol 3:hostname 4:port 5:path + query string
    // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    // 2:host
    if (!match) {
        return null;
    }
    if (!match[1]) {
        if (/^https?:/i.test(req_url)) {
            // The pattern at top could mistakenly parse "http:///" as host="http:" and path=///.
            return null;
        }
        // Scheme is omitted.
        if (req_url.lastIndexOf("//", 0) === -1) {
            // "//" is omitted.
            req_url = "//" + req_url;
        }
        req_url = (match[4] === "443" ? "https:" : "http:") + req_url;
    }
    const parsed = url.parse(req_url);
    if (!parsed.hostname) {
        // "http://:1/" and "http:/notenoughslashes" could end up here.
        return null;
    }
    return parsed;
}
function getHandler(options, proxy) {
    const corsAnywhere = {
        handleInitialRequest: null, // Function that may handle the request instead, by returning a truthy value.
        getProxyForUrl: getProxyForUrl, // Function that specifies the proxy to use
        maxRedirects: 5, // Maximum number of redirects to be followed.
        originBlacklist: [], // Requests from these origins will be blocked.
        originWhitelist: [], // If non-empty, requests not from an origin in this list will be blocked.
        checkRateLimit: null, // Function that may enforce a rate-limit by returning a non-empty string.
        redirectSameOrigin: false, // Redirect the client to the requested URL for same-origin requests.
        requireHeader: null, // Require a header to be set?
        removeHeaders: [], // Strip these request headers.
        setHeaders: {}, // Set these request headers.
        corsMaxAge: 0, // If set, an Access-Control-Max-Age header with this value (in seconds) will be added.
    };
    Object.keys(corsAnywhere).forEach(function (option) {
        if (Object.prototype.hasOwnProperty.call(options, option)) {
            corsAnywhere[option] = options[option];
        }
    });
    // Convert corsAnywhere.requireHeader to an array of lowercase header names, or null.
    if (corsAnywhere.requireHeader) {
        if (typeof corsAnywhere.requireHeader === "string") {
            (corsAnywhere as any).requireHeader = [(corsAnywhere as any).requireHeader.toLowerCase()];
        } else if (!Array.isArray(corsAnywhere.requireHeader) || (corsAnywhere as any).requireHeader.length === 0) {
            corsAnywhere.requireHeader = null;
        } else {
            corsAnywhere.requireHeader = (corsAnywhere.requireHeader as any).map(function (headerName) {
                return headerName.toLowerCase();
            });
        }
    }
    const hasRequiredHeaders = function (headers) {
        return (
            !corsAnywhere.requireHeader ||
            (corsAnywhere.requireHeader as any).some(function (headerName) {
                return Object.hasOwnProperty.call(headers, headerName);
            })
        );
    };
    return function (req, res) {
        req.corsAnywhereRequestState = {
            getProxyForUrl: corsAnywhere.getProxyForUrl,
            maxRedirects: corsAnywhere.maxRedirects,
            corsMaxAge: corsAnywhere.corsMaxAge,
        };
        const cors_headers = withCORS({}, req);
        if (req.method === "OPTIONS") {
            // Pre-flight request. Reply successfully:
            res.writeHead(200, cors_headers);
            res.end();
            return;
        }
        const location = parseURL(req.url.slice(1));
        if (corsAnywhere.handleInitialRequest && (corsAnywhere as any).handleInitialRequest(req, res, location)) {
            return;
        }
        if (!location) {
            // Special case http:/notenoughslashes, because new users of the library frequently make the
            // mistake of putting this application behind a server/router that normalizes the URL.
            // See https://github.com/Rob--W/cors-anywhere/issues/238#issuecomment-629638853
            if (/^\/https?:\/[^/]/i.test(req.url)) {
                res.writeHead(400, "Missing slash", cors_headers);
                res.end("The URL is invalid: two slashes are needed after the http(s):.");
                return;
            }
            // Invalid API call. Show how to correctly use the API
            res.end(readFileSync(join(__dirname, "../index.html")));
            return;
        }
        if (location.host === "iscorsneeded") {
            // Is CORS needed? This path is provided so that API consumers can test whether it's necessary
            // to use CORS. The server's reply is always No, because if they can read it, then CORS headers
            // are not necessary.
            res.writeHead(200, { "Content-Type": "text/plain" });
            res.end("no");
            return;
        }
        if ((Number(location.port) ?? 0) > 65535) {
            // Port is higher than 65535
            res.writeHead(400, "Invalid port", cors_headers);
            res.end("Port number too large: " + location.port);
            return;
        }
        function isValidHostName(hostname) {
            return !!(net.isIPv4(hostname) || net.isIPv6(hostname));
        }
        if (!/^\/https?:/.test(req.url) && !isValidHostName(location.hostname)) {
            // Don't even try to proxy invalid hosts (such as /favicon.ico, /robots.txt)
            const uri = new URL(req.url ?? web_server_url, "http://localhost:3000");
            if (uri.pathname === "/m3u8-proxy") {
                let headers = {};
                try {
                    headers = JSON.parse(uri.searchParams.get("headers") ?? "{}");
                } catch (e: any) {
                    res.writeHead(500);
                    res.end(e.message);
                    return;
                }
                const url = uri.searchParams.get("url");
                return proxyM3U8(url ?? "", headers, res);
            } else if (uri.pathname === "/ts-proxy") {
                let headers = {};
                try {
                    headers = JSON.parse(uri.searchParams.get("headers") ?? "{}");
                } catch (e: any) {
                    res.writeHead(500);
                    res.end(e.message);
                    return;
                }
                const url = uri.searchParams.get("url");
                return proxyTs(url ?? "", headers, req, res);
            } else if (uri.pathname === "/") {
                return res.end(readFileSync(join(__dirname, "../index.html")));
            } else {
                res.writeHead(404, "Invalid host", cors_headers);
                res.end("Invalid host: " + location.hostname);
                return;
            }
        }
        if (!hasRequiredHeaders(req.headers)) {
            res.writeHead(400, "Header required", cors_headers);
            res.end("Missing required request header. Must specify one of: " + corsAnywhere.requireHeader);
            return;
        }
        const origin = req.headers.origin || "";
        if ((corsAnywhere.originBlacklist as any[]).indexOf(origin) >= 0) {
            res.writeHead(403, "Forbidden", cors_headers);
            res.end('The origin "' + origin + '" was blacklisted by the operator of this proxy.');
            return;
        }
        if (corsAnywhere.originWhitelist.length && (corsAnywhere.originWhitelist as any[]).indexOf(origin) === -1) {
            res.writeHead(403, "Forbidden", cors_headers);
            res.end('The origin "' + origin + '" was not whitelisted by the operator of this proxy.');
            return;
        }
        const rateLimitMessage = corsAnywhere.checkRateLimit && (corsAnywhere as any).checkRateLimit(origin);
        if (rateLimitMessage) {
            res.writeHead(429, "Too Many Requests", cors_headers);
            res.end('The origin "' + origin + '" has sent too many requests.\n' + rateLimitMessage);
            return;
        }
        if (corsAnywhere.redirectSameOrigin && origin && location.href[origin.length] === "/" && location.href.lastIndexOf(origin, 0) === 0) {
            // Send a permanent redirect to offload the server. Badly coded clients should not waste our resources.
            cors_headers.vary = "origin";
            cors_headers["cache-control"] = "private";
            cors_headers.location = location.href;
            res.writeHead(301, "Please use a direct request", cors_headers);
            res.end();
            return;
        }
        const isRequestedOverHttps = req.connection.encrypted || /^\s*https/.test(req.headers["x-forwarded-proto"]);
        const proxyBaseUrl = (isRequestedOverHttps ? "https://" : "http://") + req.headers.host;
        corsAnywhere.removeHeaders.forEach(function (header) {
            delete req.headers[header];
        });
        Object.keys(corsAnywhere.setHeaders).forEach(function (header) {
            req.headers[header] = corsAnywhere.setHeaders[header];
        });
        req.corsAnywhereRequestState.location = location;
        req.corsAnywhereRequestState.proxyBaseUrl = proxyBaseUrl;
        proxyRequest(req, res, proxy);
    };
}
// Create server with default and given values
// Creator still needs to call .listen()
function createServer(options) {
    options = options || {};
    // Default options:
    const httpProxyOptions = {
        xfwd: true, // Append X-Forwarded-* headers
        secure: process.env.NODE_TLS_REJECT_UNAUTHORIZED !== "0",
    };
    // Allow user to override defaults and add own options
    if (options.httpProxyOptions) {
        Object.keys(options.httpProxyOptions).forEach(function (option) {
            httpProxyOptions[option] = options.httpProxyOptions[option];
        });
    }
    const proxyServer = httpProxy.createServer(httpProxyOptions);
    const requestHandler = getHandler(options, proxyServer);
    let server: Server;
    if (options.httpsOptions) {
        server = https.createServer(options.httpsOptions, requestHandler);
    } else {
        server = http.createServer(requestHandler);
    }
    // When the server fails, just show a 404 instead of Internal server error
    proxyServer.on("error", function (err, req, res) {
        if (res.headersSent) {
            // This could happen when a protocol error occurs when an error occurs
            // after the headers have been received (and forwarded). Do not write
            // the headers because it would generate an error.
            // Prior to Node 13.x, the stream would have ended.
            // As of Node 13.x, we must explicitly close it.
            if (res.writableEnded === false) {
                res.end();
            }
            return;
        }
        // When the error occurs after setting headers but before writing the response,
        // then any previously set headers must be removed.
        const headerNames = res.getHeaderNames ? res.getHeaderNames() : Object.keys(res._headers || {});
        headerNames.forEach(function (name) {
            res.removeHeader(name);
        });
        res.writeHead(404, { "Access-Control-Allow-Origin": "*" });
        res.end("Not found because of proxy error: " + err);
    });
    return server;
}
const host = process.env.HOST || "0.0.0.0";
const port = process.env.PORT || 8080;
const web_server_url = process.env.PUBLIC_URL;
export default function server() {
    const originBlacklist = parseEnvList(process.env.CORSANYWHERE_BLACKLIST);
    const originWhitelist = parseEnvList(process.env.CORSANYWHERE_WHITELIST);
    function parseEnvList(env) {
        if (!env) {
            return [];
        }
        return env.split(",");
    }
    createServer({
        originBlacklist: [], // Force empty blacklist to allow all origins
        originWhitelist: [], // Force empty whitelist to disable whitelist check
        requireHeader: [],
        checkRateLimit: null, // Disable rate limiting
        removeHeaders: [
            "cookie",
            "cookie2",
            // Strip Heroku-specific headers
            "x-request-start",
            "x-request-id",
            "via",
            "connect-time",
            "total-route-time",
            // Other Heroku added debug headers
            // 'x-forwarded-for',
            // 'x-forwarded-proto',
            // 'x-forwarded-port',
        ],
        redirectSameOrigin: true,
        httpProxyOptions: {
            // Do not add X-Forwarded-For, etc. headers, because Heroku already adds it.
            xfwd: false,
        },
    }).listen(port, Number(host), function () {
        console.log(colors.green("Server running on ") + colors.blue(`${web_server_url}`));
    });
}
function createRateLimitChecker(CORSANYWHERE_RATELIMIT) {
    // Configure rate limit. The following format is accepted for CORSANYWHERE_RATELIMIT:
    // <max requests per period> <period in minutes> <non-ratelimited hosts>
    // where <non-ratelimited hosts> is a space-separated list of strings or regexes (/.../) that
    // matches the whole host (ports have to be listed explicitly if applicable).
    // <period in minutes> cannot be zero.
    //
    // Examples:
    // - Allow any origin to make one request per 5 minutes:
    // 1 5
    //
    // - Allow example.com to make an unlimited number of requests, and the others 1 per 5 minutes.
    // 1 5 example.com
    //
    // - Allow example.com, or any subdomain to make any number of requests and block the rest:
    // 0 1 /(.*\.)?example\.com/
    //
    // - Allow example.com and www.example.com, and block the rest:
    // 0 1 example.com www.example.com
    const rateLimitConfig = /^(\d+) (\d+)(?:\s*$|\s+(.+)$)/.exec(CORSANYWHERE_RATELIMIT);
    if (!rateLimitConfig) {
        // No rate limit by default.
        return function checkRateLimit() {};
    }
    const maxRequestsPerPeriod = parseInt(rateLimitConfig[1]);
    const periodInMinutes = parseInt(rateLimitConfig[2]);
    let unlimitedPattern: any = rateLimitConfig[3]; // Will become a RegExp or void.
    if (unlimitedPattern) {
        const unlimitedPatternParts: string[] = [];
        unlimitedPattern
            .trim()
            .split(/\s+/)
            .forEach(function (unlimitedHost, i) {
                const startsWithSlash = unlimitedHost.charAt(0) === "/";
                const endsWithSlash = unlimitedHost.slice(-1) === "/";
                if (startsWithSlash || endsWithSlash) {
                    if (unlimitedHost.length === 1 || !startsWithSlash || !endsWithSlash) {
                        throw new Error("Invalid CORSANYWHERE_RATELIMIT. Regex at index " + i + ' must start and end with a slash ("/").');
                    }
                    unlimitedHost = unlimitedHost.slice(1, -1);
                    // Throws if the pattern is invalid.
                    new RegExp(unlimitedHost);
                } else {
                    // Just escape RegExp characters even though they cannot appear in a host name.
                    // The only actual important escape is the dot.
                    unlimitedHost = unlimitedHost.replace(/[$()*+.?[\\\]^{|}]/g, "\\$&");
                }
                unlimitedPatternParts.push(unlimitedHost);
            });
        unlimitedPattern = new RegExp("^(?:" + unlimitedPatternParts.join("|") + ")$", "i");
    }
    let accessedHosts = Object.create(null);
    setInterval(function () {
        accessedHosts = Object.create(null);
    }, periodInMinutes * 60000);
    const rateLimitMessage = "The number of requests is limited to " + maxRequestsPerPeriod + (periodInMinutes === 1 ? " per minute" : " per " + periodInMinutes + " minutes") + ". " + "Please self-host CORS Anywhere if you need more quota. " + "See https://github.com/Rob--W/cors-anywhere#demo-server";
    return function checkRateLimit(origin) {
        const host = origin.replace(/^[\w\-]+:\/\//i, "");
        if (unlimitedPattern && unlimitedPattern.test(host)) {
            return;
        }
        let count = accessedHosts[host] || 0;
        ++count;
        if (count > maxRequestsPerPeriod) {
            return rateLimitMessage;
        }
        accessedHosts[host] = count;
    };
}
/**
 * @description Proxies m3u8 files and replaces the content to point to the proxy.
 * @param headers JSON headers
 * @param res Server response object
 */
export async function proxyM3U8(url: string, headers: any, res: http.ServerResponse) {
    const req = await axios(url, {
        headers: headers,
    }).catch((err) => {
        res.writeHead(500);
        res.end(err.message);
        return null;
    });
    if (!req) {
        return;
    }
    const m3u8 = req.data;
    if (m3u8.includes("RESOLUTION=")) {
        // Deals with the master m3u8 and replaces all sub-m3u8 files (quality m3u8 files basically) to use the m3u8 proxy.
        // So if there is 360p, 480p, etc. Instead, the URL's of those m3u8 files will be replaced with the proxy URL.
        const lines = m3u8.split("\n");
        const newLines: string[] = [];
        for (const line of lines) {
            if (line.startsWith("#")) {
                if (line.startsWith("#EXT-X-KEY:")) {
                    const regex = /https?:\/\/[^\""\s]+/g;
                    const keyUrl = regex.exec(line)?.[0] ?? "";
                    const proxiedUrl = `${web_server_url}/ts-proxy?url=${encodeURIComponent(keyUrl)}&headers=${encodeURIComponent(JSON.stringify(headers))}`;
                    newLines.push(line.replace(keyUrl, proxiedUrl));
                } else {
                    newLines.push(line);
                }
            } else if (line.trim() !== "") {
                const uri = new URL(line, url);
                newLines.push(`${web_server_url}/m3u8-proxy?url=${encodeURIComponent(uri.href)}&headers=${encodeURIComponent(JSON.stringify(headers))}`);
            }
        }
        // Remove unnecessary headers
        ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Max-Age", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers", "Access-Control-Request-Method", "Access-Control-Request-Headers", "Origin", "Vary", "Referer", "Server", "x-cache", "via", "x-amz-cf-pop", "x-amz-cf-id"].map((header) => res.removeHeader(header));
        // Set required headers
        res.setHeader("Content-Type", "application/vnd.apple.mpegurl");
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Headers", "*");
        res.setHeader("Access-Control-Allow-Methods", "*");
        res.end(newLines.join("\n"));
        return;
    } else {
        // Deals with each individual quality. Replaces the TS files with the proxy URL.
        const lines = m3u8.split("\n");
        const newLines: string[] = [];
        for (const line of lines) {
            if (line.startsWith("#")) {
                if (line.startsWith("#EXT-X-KEY:")) {
                    const regex = /https?:\/\/[^\""\s]+/g;
                    const keyUrl = regex.exec(line)?.[0] ?? "";
                    const proxiedUrl = `${web_server_url}/ts-proxy?url=${encodeURIComponent(keyUrl)}&headers=${encodeURIComponent(JSON.stringify(headers))}`;
                    newLines.push(line.replace(keyUrl, proxiedUrl));
                } else {
                    newLines.push(line);
                }
            } else if (line.trim() !== "") {
                const uri = new URL(line, url);
                newLines.push(`${web_server_url}/ts-proxy?url=${encodeURIComponent(uri.href)}&headers=${encodeURIComponent(JSON.stringify(headers))}`);
            }
        }
        // Remove unnecessary headers
        ["Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Max-Age", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers", "Access-Control-Request-Method", "Access-Control-Request-Headers", "Origin", "Vary", "Referer", "Server", "x-cache", "via", "x-amz-cf-pop", "x-amz-cf-id"].map((header) => res.removeHeader(header));
        // Set required headers
        res.setHeader("Content-Type", "application/vnd.apple.mpegurl");
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Headers", "*");
        res.setHeader("Access-Control-Allow-Methods", "*");
        res.end(newLines.join("\n"));
        return;
    }
}
/**
 * @description Proxies TS files. Sometimes TS files require headers to be sent with the request.
 * @param headers JSON headers
 * @param req Client request object
 * @param res Server response object
 */
export async function proxyTs(url: string, headers: any, req, res: http.ServerResponse) {
    if (req.method === "OPTIONS") {
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Headers", "*");
        res.setHeader("Access-Control-Allow-Methods", "*");
        res.writeHead(200);
        res.end();
        return;
    }
    // I love how NodeJS HTTP request client only takes http URLs :D It's so fun!
    // I'll probably refactor this later.
    let forceHTTPS = false;
    if (url.startsWith("https://")) {
        forceHTTPS = true;
    }
    const uri = new URL(url);
    // Options
    // It might be worth adding ...req.headers to the headers object, but once I did that
    // the code broke and I receive errors such as "Cannot access direct IP" or whatever.
    const options = {
        hostname: uri.hostname,
        port: uri.port,
        path: uri.pathname + uri.search,
        method: req.method,
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36",
            ...headers,
        },
    };
    // Proxy request and pipe to client
    try {
        let proxy;
        if (forceHTTPS) {
            proxy = https.request(options, (r) => {
                // Set content type
                r.headers["content-type"] = "video/mp2t";
                // Add CORS headers
                r.headers["access-control-allow-origin"] = "*";
                r.headers["access-control-allow-headers"] = "*";
                r.headers["access-control-allow-methods"] = "*";
                // Remove unnecessary headers
                ["access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "access-control-max-age", "access-control-allow-credentials", "access-control-expose-headers", "access-control-request-method", "access-control-request-headers", "origin", "vary", "referer", "server", "x-cache", "via", "x-amz-cf-pop", "x-amz-cf-id"].forEach((header) => {
                    delete r.headers[header.toLowerCase()];
                });
                res.writeHead(r.statusCode ?? 200, r.headers);
                r.pipe(res, {
                    end: true,
                });
            });
            req.pipe(proxy, {
                end: true,
            });
        } else {
            proxy = http.request(options, (r) => {
                // Set content type
                r.headers["content-type"] = "video/mp2t";
                // Add CORS headers
                r.headers["access-control-allow-origin"] = "*";
                r.headers["access-control-allow-headers"] = "*";
                r.headers["access-control-allow-methods"] = "*";
                // Remove unnecessary headers
                ["access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "access-control-max-age", "access-control-allow-credentials", "access-control-expose-headers", "access-control-request-method", "access-control-request-headers", "origin", "vary", "referer", "server", "x-cache", "via", "x-amz-cf-pop", "x-amz-cf-id"].forEach((header) => {
                    delete r.headers[header.toLowerCase()];
                });
                res.writeHead(r.statusCode ?? 200, r.headers);
                r.pipe(res, {
                    end: true,
                });
            });
            req.pipe(proxy, {
                end: true,
            });
        }
    } catch (e: any) {
        res.writeHead(500);
        res.end(e.message);
        return null;
    }
}
