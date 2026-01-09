import dotenv from "dotenv";
dotenv.config();

import http from "node:http";
import https from "node:https";
import { URL } from "url";
import axios from "axios";
import { readFileSync } from "fs";
import { join } from "path";
import colors from "colors";

const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || "0.0.0.0";
const WEB_SERVER_URL = process.env.PUBLIC_URL || `http://localhost:${PORT}`;

function setCORSHeaders(res: http.ServerResponse) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "*");
  res.setHeader("Access-Control-Allow-Methods", "*");
}

async function proxyM3U8(url: string, headers: any, res: http.ServerResponse) {
  try {
    const response = await axios.get(url, { headers });
    const m3u8 = response.data as string;
    const lines = m3u8.split("\n");
    const newLines: string[] = [];

    for (const line of lines) {
      if (line.startsWith("#EXT-X-KEY:")) {
        const regex = /https?:\/\/[^\""\s]+/g;
        const keyUrl = regex.exec(line)?.[0] ?? "";
        const proxiedUrl = `${WEB_SERVER_URL}/ts-proxy?url=${encodeURIComponent(keyUrl)}&headers=${encodeURIComponent(JSON.stringify(headers))}`;
        newLines.push(line.replace(keyUrl, proxiedUrl));
      } else if (!line.startsWith("#") && line.trim() !== "") {
        const uri = new URL(line, url);
        newLines.push(`${WEB_SERVER_URL}/ts-proxy?url=${encodeURIComponent(uri.href)}&headers=${encodeURIComponent(JSON.stringify(headers))}`);
      } else {
        newLines.push(line);
      }
    }

    setCORSHeaders(res);
    res.setHeader("Content-Type", "application/vnd.apple.mpegurl");
    res.end(newLines.join("\n"));
  } catch (err: any) {
    res.writeHead(500);
    res.end(err.message);
  }
}

function proxyTS(url: string, headers: any, req: http.IncomingMessage, res: http.ServerResponse) {
  if (req.method === "OPTIONS") {
    setCORSHeaders(res);
    res.writeHead(200);
    res.end();
    return;
  }

  const uri = new URL(url);
  const options = {
    hostname: uri.hostname,
    port: uri.port || (uri.protocol === "https:" ? 443 : 80),
    path: uri.pathname + uri.search,
    method: req.method,
    headers: {
      "User-Agent": "Mozilla/5.0",
      ...headers,
    },
  };

  const client = uri.protocol === "https:" ? https : http;
  const proxyReq = client.request(options, (proxyRes) => {
    proxyRes.headers["content-type"] = "video/mp2t";
    setCORSHeaders(proxyRes);
    res.writeHead(proxyRes.statusCode ?? 200, proxyRes.headers);
    proxyRes.pipe(res);
  });

  req.pipe(proxyReq);
  proxyReq.on("error", (err) => {
    res.writeHead(500);
    res.end(err.message);
  });
}

const server = http.createServer((req, res) => {
  if (!req.url) return res.end("Invalid request");

  const urlObj = new URL(req.url, `http://${req.headers.host}`);
  const targetUrl = urlObj.searchParams.get("url");
  const headers = JSON.parse(urlObj.searchParams.get("headers") || "{}");

  if (req.url.startsWith("/m3u8-proxy")) {
    if (!targetUrl) return res.end("Missing url");
    return proxyM3U8(targetUrl, headers, res);
  }

  if (req.url.startsWith("/ts-proxy")) {
    if (!targetUrl) return res.end("Missing url");
    return proxyTS(targetUrl, headers, req, res);
  }

  // Default root page
  res.end(readFileSync(join(__dirname, "../index.html")));
});

server.listen(PORT, HOST, () => {
  console.log(colors.green("CORS proxy running at: ") + colors.blue(`${WEB_SERVER_URL}`));
});
