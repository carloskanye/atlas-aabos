// ============================================================
// ATLAS AABOS — Knowledge Embed Service v1.0
// supabase/functions/knowledge-embed/index.ts
//
// Triggered by the frontend the moment a knowledge entry is saved,
// or manually via the backfill action for pre-existing entries.
//
// Note: no SUPABASE_SERVICE_ROLE_KEY needed here. Knowledge reads/writes
// respect RLS through the caller's own JWT; the registry functions are
// SECURITY DEFINER and work correctly through any authenticated client.
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
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, event, service: "knowledge-embed", ...meta }));
}

function json(body: unknown, status: number, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...headers, "Content-Type": "application/json" } });
}

// ── Call Cohere, return the raw float array ────────────────────
async function embedText(text: string, inputType: "search_document" | "search_query"): Promise<number[]> {
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
        texts:      [text.slice(0, 4000)], // keep well under the model's per-text guidance
        model:      COHERE_MODEL,
        input_type: inputType,
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
    if ((err as Error)?.name === "AbortError") throw new Error("Embedding request timed out");
    throw err;
  }
}

// pgvector expects a literal string like "[0.1,0.2,0.3]" — explicit
// string construction avoids relying on JS-array-to-vector coercion
// behaving correctly through PostgREST for every client version.
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

  const entryId = (raw as { entryId?: unknown })?.entryId;
  if (typeof entryId !== "string" || entryId.length === 0) {
    return json({ error: "entryId is required" }, 400, corsHeaders);
  }

  // ── Fetch the entry — RLS ensures the user can only embed their own ──
  const { data: entry, error: fetchErr } = await sb
    .from("knowledge")
    .select("id, title, content")
    .eq("id", entryId)
    .single();

  if (fetchErr || !entry) {
    return json({ error: "Knowledge entry not found" }, 404, corsHeaders);
  }

  const startMs = Date.now();
  try {
    // Title + content gives the embedding more semantic signal than content alone
    const embedText_ = `${entry.title}\n\n${entry.content}`;
    const vector = await embedText(embedText_, "search_document");

    const { error: updateErr } = await sb
      .from("knowledge")
      .update({ embedding: toVectorLiteral(vector), embedding_status: "completed" })
      .eq("id", entryId);

    if (updateErr) throw new Error(updateErr.message);

    // ── Atlas Core — heartbeat + event, both fire-and-forget ─────
    sb.rpc("heartbeat_atlas_entity", { p_entity_key: "knowledge", p_status: "online" })
      .then(() => {}).catch(() => {});
    sb.rpc("heartbeat_atlas_entity", { p_entity_key: "knowledge-embed", p_status: "online" })
      .then(() => {}).catch(() => {});
    sb.rpc("log_atlas_event", {
      p_event_type: "knowledge.document.indexed",
      p_entity_key: "knowledge",
      p_payload: { entry_id: entryId, title: entry.title, dimensions: vector.length, duration_ms: Date.now() - startMs },
    }).then(() => {}).catch(() => {});

    log("info", "entry_embedded", { entryId, durationMs: Date.now() - startMs });

    return json({ success: true, entryId, dimensions: vector.length }, 200, corsHeaders);

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log("error", "embed_failed", { entryId, error: msg });

    await sb.from("knowledge").update({ embedding_status: "failed" }).eq("id", entryId).catch(() => {});

    return json({ success: false, error: msg }, 502, corsHeaders);
  }
});
