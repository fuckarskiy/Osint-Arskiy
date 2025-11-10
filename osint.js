/**
 * osint.js — single-file OSINT aggregator (Node.js)
 *
 * - One file: serves frontend + API
 * - No external dependencies (Node 18+ recommended because of global fetch)
 * - Run: node osint.js
 * - Open: http://localhost:3000
 *
 * Endpoints:
 *  GET /                -> frontend UI
 *  GET /api/search?type=ip|domain|phone|nick|email&q=...
 *
 * Notes:
 *  - IP search: ip-api.com (geo), rdap.org (rdap), DNS via dns.promises
 *  - Phone: simple normalization + DuckDuckGo search aggregation
 *  - DuckDuckGo: uses html.duckduckgo.com/html/?q=... and extracts top results
 *
 * Use responsibly.
 */

import http from "http";
import url from "url";
import dns from "dns/promises";
import { StringDecoder } from "string_decoder";
import { fileURLToPath } from "url";
import { dirname } from "path";

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

/* ----------------- Utilities ----------------- */

function safeEncode(s = "") {
  return encodeURIComponent(String(s));
}

async function fetchText(u, opts = {}) {
  const res = await fetch(u, opts);
  return await res.text();
}

async function fetchJson(u, opts = {}) {
  const res = await fetch(u, opts);
  return await res.json();
}

/* ----------------- DuckDuckGo scraper (minimal) ----------------- */
async function duckDuckGoSearch(query, maxResults = 6) {
  const url = `https://html.duckduckgo.com/html/?q=${safeEncode(query)}`;
  try {
    const text = await fetchText(url, { headers: { "User-Agent": "OSINT-Aggregator/1.0" }});
    // crude parse: find <a class="result__a" href="...">title</a> and snippet in .result__snippet
    const results = [];
    // Split by result container to reduce false matches
    const parts = text.split('<div class="result');
    for (const part of parts.slice(1)) {
      if (results.length >= maxResults) break;
      // link
      const hrefMatch = part.match(/<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"/i) || part.match(/<a[^>]*href="([^"]+)"[^>]*>/i);
      const titleMatch = part.match(/<a[^>]*class="[^"]*result__a[^"]*"[^>]*>(.*?)<\/a>/is) || part.match(/<a[^>]*>(.*?)<\/a>/is);
      const snippetMatch = part.match(/class="result__snippet"[^>]*>([\s\S]*?)<\/div>/i);
      const href = hrefMatch ? hrefMatch[1] : null;
      let title = titleMatch ? titleMatch[1].replace(/<\/?[^>]+(>|$)/g, "").trim() : null;
      let snippet = snippetMatch ? snippetMatch[1].replace(/<\/?[^>]+(>|$)/g, "").trim() : "";
      if (href) {
        // duckduckgo sometimes returns redirect links or relative; keep as-is
        results.push({ title: title || href, snippet, link: href });
      }
    }
    return results;
  } catch (e) {
    console.error("DDG search error:", e && e.message);
    return [];
  }
}

/* ----------------- IP tools ----------------- */
async function ipGeolocation(ip) {
  try {
    const res = await fetchJson(`http://ip-api.com/json/${safeEncode(ip)}?fields=status,message,country,regionName,city,zip,lat,lon,isp,org,query`);
    return res;
  } catch (e) {
    return { status: "fail", message: e.message };
  }
}

async function rdapLookup(kind, name) {
  try {
    const prefix = kind === "ip" ? "ip" : "domain";
    const url = `https://rdap.org/${prefix}/${safeEncode(name)}`;
    const res = await fetch(url, { headers: { "User-Agent": "OSINT-Aggregator/1.0" }});
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    return null;
  }
}

async function dnsRecords(name) {
  const out = {};
  try { out.A = await dns.resolve(name, "A").catch(()=>[]); } catch { out.A = []; }
  try { out.AAAA = await dns.resolve(name, "AAAA").catch(()=>[]); } catch { out.AAAA = []; }
  try { out.MX = await dns.resolveMx(name).catch(()=>[]); } catch { out.MX = []; }
  try { out.TXT = await dns.resolveTxt(name).catch(()=>[]); } catch { out.TXT = []; }
  try { out.NS = await dns.resolveNs(name).catch(()=>[]); } catch { out.NS = []; }
  try { out.CNAME = await dns.resolveCname(name).catch(()=>[]); } catch { out.CNAME = []; }
  return out;
}

/* ----------------- Phone helpers ----------------- */
function normalizePhone(raw) {
  if (!raw) return null;
  // remove common punctuation, keep leading +
  let s = String(raw).trim();
  // Replace parentheses and spaces etc.
  s = s.replace(/[^\d+]/g, "");
  // If multiple +'s, remove extras
  s = s.replace(/^(\+)+/, "+");
  // If starts with 00 (international prefix), replace with +
  if (s.startsWith("00")) s = "+" + s.slice(2);
  // create simple E.164-like form if starts with + and digits
  const digits = s.replace(/\D/g, "");
  const e164 = s.startsWith("+") ? "+" + digits : digits;
  return { raw, cleaned: s, digits, e164 };
}

/* ----------------- Helpers ----------------- */
function looksLikeIP(q) {
  return /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(q) || q.includes(":");
}

/* ----------------- API runner ----------------- */
async function perform