// ============================================================
// ATLAS AABOS — Knowledge Search Service v1.0
// supabase/functions/knowledge-search/index.ts
//
// Embeds the user's query with input_type=search_query (NOT
// search_document — using the wrong one measurably hurts retrieval
// quality even though both accept the same request shape) and
// ranks knowledge entries by cosine similarity via match_knowledge().
// ============================================================

import { serve }        from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL   = Deno.env.get("SUPABASE_URL")      ?? "";
const SUPABASE_ANON  = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
const COHERE_API_KEY = Deno.env.get("COHERE_API_KEY")    ?? "";
const COHERE_URL     = "https://api.cohere.com/v1/embed";
const COHERE_MODEL   = "embed-english-v3.0";
const ALLOWED_ORIGINS = (Deno.env.get("ALLOWED_ORIGIN") ?? "*")
                        .split(",").map(o => o.trim()).filter(Boolean);
const TIMEOUT_MS = 15_000;
const MAX_QUERY_LENGTH = 500;
const DEFAULT_MATCH_COUNT = 5;
const MAX_MATCH_COUNT = 20;

function buildCorsHeaders(origin: string | null): Record<string, string> {
  const isWildcard = ALLOWED_ORIGINS.includes("*");
  const isAllowed  = isWildcard || (origin !== null && ALLOWED_ORIGINS.includes(origin));
  const allowedOrigin = isWildcard ? "*" : (isAllowed && origin ? origin : "null");
  return {
    "Access-Control-Allow-Origin":  allowedOrigin,
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age":       "86400",
    "Vary":                         "Origin",
  };
}

function log(level: string, event: string, meta: Record<string, unknown> = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, event, service: "knowledge-search", ...meta }));
}

function json(body: unknown, status: number, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...headers, "Content-Type": "application/json" } });
}

async function embedQuery(text: string): Promise<number[]> {
  const controller = new AbortController();
  const timeout    = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const resp = await fetch(COHERE_URL, {
      method:  "POST",
      signal:  controller.signal,
      headers: {
        "Authorization": `Bearer ${COHERE_API_KEY}`,
        "Content-Type":  "application/json",
      },
      body: JSON.stringify({
        texts:      [text],
        model:      COHERE_MODEL,
        input_type: "search_query", // deliberately different from indexing — see file header
      }),
    });
    clearTimeout(timeout);

    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`Cohere ${resp.status}: ${body.slice(0, 200)}`);
    }

    const data = await resp.json();
    const embedding = data.embeddings?.[0];
    if (!Array.isArray(embedding)) throw new Error("Cohere returned no embedding vector");
    return embedding;
  } catch (err) {
    clearTimeout(timeout);
    if ((err as Error)?.name === "AbortError") throw new Error("Search request timed out");
    throw err;
  }
}

function toVectorLiteral(vec: number[]): string {
  return `[${vec.join(",")}]`;
}

serve(async (req: Request) => {
  const origin      = req.headers.get("origin");
  const corsHeaders = buildCorsHeaders(origin);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405, corsHeaders);
  }
  if (!COHERE_API_KEY) {
    log("error", "missing_cohere_key");
    return json({ error: "Knowledge Engine not configured" }, 500, corsHeaders);
  }

  const authHeader = req.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return json({ error: "Authentication required" }, 401, corsHeaders);
  }

  const sb = createClient(SUPABASE_URL, SUPABASE_ANON, {
    global: { headers: { Authorization: authHeader } },
  });

  const { data: { user }, error: authErr } = await sb.auth.getUser();
  if (authErr || !user) {
    return json({ error: "Unauthorized" }, 401, corsHeaders);
  }

  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400, corsHeaders);
  }

  const body = raw as { query?: unknown; matchCount?: unknown };
  const query = body?.query;
  if (typeof query !== "string" || query.trim().length === 0) {
    return json({ error: "query is required" }, 400, corsHeaders);
  }
  if (query.length > MAX_QUERY_LENGTH) {
    return json({ error: `query exceeds ${MAX_QUERY_LENGTH} characters` }, 400, corsHeaders);
  }

  let matchCount = DEFAULT_MATCH_COUNT;
  if (body.matchCount !== undefined) {
    const n = Number(body.matchCount);
    if (!Number.isInteger(n) || n < 1 || n > MAX_MATCH_COUNT) {
      return json({ error: `matchCount must be an integer between 1 and ${MAX_MATCH_COUNT}` }, 400, corsHeaders);
    }
    matchCount = n;
  }

  const startMs = Date.now();
  try {
    const vector = await embedQuery(query);

    const { data: results, error: matchErr } = await sb.rpc("match_knowledge", {
      p_query_embedding: toVectorLiteral(vector),
      p_match_count:     matchCount,
      p_min_similarity:  0.3,
    });

    if (matchErr) throw new Error(matchErr.message);

    // ── Atlas Core — heartbeat + event, both fire-and-forget ─────
    sb.rpc("heartbeat_atlas_entity", { p_entity_key: "knowledge", p_status: "online" })
      .then(() => {}).catch(() => {});
    sb.rpc("heartbeat_atlas_entity", { p_entity_key: "knowledge-search", p_status: "online" })
      .then(() => {}).catch(() => {});
    sb.rpc("log_atlas_event", {
      p_event_type: "knowledge.search.performed",
      p_entity_key: "knowledge",
      p_payload: { query: query.slice(0, 100), results_count: results?.length ?? 0, duration_ms: Date.now() - startMs },
    }).then(() => {}).catch(() => {});

    log("info", "search_completed", { resultsCount: results?.length ?? 0, durationMs: Date.now() - startMs });

    return json({ success: true, results: results ?? [], durationMs: Date.now() - startMs }, 200, corsHeaders);

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log("error", "search_failed", { error: msg });
    return json({ success: false, error: msg }, 502, corsHeaders);
  }
});
