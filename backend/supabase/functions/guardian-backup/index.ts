// ============================================================
// ATLAS AABOS — Guardian Backup Engine v1.2
// supabase/functions/guardian-backup/index.ts
//
// Runs nightly at 01:30 via pg_cron (30 min after health scan)
// Exports all Atlas data to GitHub private repository
// Records manifest with checksums in guardian_manifests
//
// v1.1: Added CORS headers — required for browser calls
// v1.2: Logs guardian.backup.completed to the Atlas Event Log
// ============================================================

import { serve }        from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL  = Deno.env.get("SUPABASE_URL")             ?? "";
const SUPABASE_SVC  = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const GITHUB_PAT    = Deno.env.get("GITHUB_PAT")               ?? "";
const GITHUB_REPO   = Deno.env.get("GITHUB_REPO")              ?? "";
const ALLOWED_ORIGINS = (Deno.env.get("ALLOWED_ORIGIN") ?? "*")
                        .split(",").map(o => o.trim()).filter(Boolean);

// ── CORS headers — matches ai-gateway pattern ─────────────────
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

const BACKUP_TABLES = [
  "businesses", "tasks", "revenue_logs", "expenses",
  "affiliate_links", "content_queue", "knowledge",
  "trends", "subscriptions", "plans",
  "guardian_reports", "guardian_alerts", "guardian_manifests"
];

const MAX_ROWS = 10000;

function log(level: string, event: string, meta: Record<string, unknown> = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    level, event,
    service: "guardian-backup",
    ...meta
  }));
}

async function sha256(content: string): Promise<string> {
  const buffer = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(content)
  );
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64(content: string): string {
  const bytes = new TextEncoder().encode(content);
  let binary = "";
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}

async function getFileSha(path: string): Promise<string | null> {
  const url = `https://api.github.com/repos/${GITHUB_REPO}/contents/${path}`;
  const resp = await fetch(url, {
    headers: {
      "Authorization": `Bearer ${GITHUB_PAT}`,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    }
  });
  if (!resp.ok) return null;
  const data = await resp.json();
  return data.sha ?? null;
}

async function pushToGitHub(
  path: string,
  content: string,
  message: string
): Promise<{ success: boolean; url: string | null; error?: string }> {
  const encoded = toBase64(content);
  const existingSha = await getFileSha(path);

  const body: Record<string, string> = {
    message,
    content: encoded,
    branch: "main",
  };
  if (existingSha) body.sha = existingSha;

  const url = `https://api.github.com/repos/${GITHUB_REPO}/contents/${path}`;
  const resp = await fetch(url, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${GITHUB_PAT}`,
      "Accept": "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const err = await resp.text();
    return { success: false, url: null, error: `GitHub ${resp.status}: ${err}` };
  }

  const result = await resp.json();
  return {
    success: true,
    url: result.content?.html_url ?? `https://github.com/${GITHUB_REPO}`,
  };
}

// ── Main handler ──────────────────────────────────────────────
serve(async (req: Request) => {
  const origin      = req.headers.get("origin");
  const corsHeaders = buildCorsHeaders(origin);

  // Handle preflight — THIS WAS MISSING IN v1.0
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const startMs  = Date.now();
  const today    = new Date().toISOString().split("T")[0];
  const backupId = crypto.randomUUID();

  log("info", "backup_started", { date: today, backupId });

  if (!SUPABASE_URL || !SUPABASE_SVC || !GITHUB_PAT || !GITHUB_REPO) {
    log("error", "missing_env_vars", {
      hasUrl: !!SUPABASE_URL,
      hasSvc: !!SUPABASE_SVC,
      hasPat: !!GITHUB_PAT,
      hasRepo: !!GITHUB_REPO,
    });
    return new Response(JSON.stringify({ error: "Missing environment variables" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  const sb = createClient(SUPABASE_URL, SUPABASE_SVC);

  const { data: manifest } = await sb
    .from("guardian_manifests")
    .insert({
      backup_date:  today,
      backup_type:  "nightly",
      destination:  "github",
      status:       "pending",
    })
    .select()
    .single();

  const manifestId = manifest?.id ?? backupId;

  try {
    const tableResults: Array<{
      name: string;
      rows: number;
      checksum: string;
      path: string;
      success: boolean;
      error?: string;
    }> = [];

    let totalRows      = 0;
    let totalSizeBytes = 0;
    let allSuccess     = true;

    for (const table of BACKUP_TABLES) {
      log("info", "exporting_table", { table });

      try {
        const { data, error } = await sb
          .from(table)
          .select("*")
          .limit(MAX_ROWS);

        if (error) throw new Error(error.message);

        const rows    = data ?? [];
        const content = JSON.stringify(rows, null, 2);
        const checksum = await sha256(content);
        const path     = `backups/${today}/tables/${table}.json`;

        const pushResult = await pushToGitHub(
          path,
          content,
          `Guardian backup ${today} — ${table} (${rows.length} rows)`
        );

        const sizeBytes = new TextEncoder().encode(content).length;
        totalSizeBytes += sizeBytes;
        totalRows      += rows.length;

        tableResults.push({
          name:     table,
          rows:     rows.length,
          checksum,
          path,
          success:  pushResult.success,
          error:    pushResult.error,
        });

        if (!pushResult.success) {
          allSuccess = false;
          log("error", "table_backup_failed", { table, error: pushResult.error });
        } else {
          log("info", "table_backed_up", {
            table, rows: rows.length, sizeBytes, checksum: checksum.slice(0, 16)
          });
        }

      } catch (tableErr) {
        const msg = tableErr instanceof Error ? tableErr.message : String(tableErr);
        allSuccess = false;
        tableResults.push({ name: table, rows: 0, checksum: "", path: "", success: false, error: msg });
        log("error", "table_export_failed", { table, error: msg });
      }
    }

    const manifestContent = JSON.stringify({
      backup_date:        today,
      backup_id:          manifestId,
      atlas_version:      "1.0",
      guardian_version:   "1.1",
      destination:        "github",
      repository:         GITHUB_REPO,
      tables:             tableResults,
      total_rows:         totalRows,
      total_size_bytes:   totalSizeBytes,
      all_successful:     allSuccess,
      completed_at:       new Date().toISOString(),
    }, null, 2);

    const manifestChecksum = await sha256(manifestContent);

    await pushToGitHub(
      `backups/${today}/manifest.json`,
      manifestContent,
      `Guardian backup ${today} — manifest`
    );

    const checksumLines = tableResults
      .filter(t => t.checksum)
      .map(t => `${t.checksum}  ${t.path}`)
      .join("\n");

    await pushToGitHub(
      `backups/${today}/checksums.sha256`,
      checksumLines,
      `Guardian backup ${today} — checksums`
    );

    const successCount = tableResults.filter(t => t.success).length;
    const failCount    = tableResults.filter(t => !t.success).length;

    const summaryLines = [
      `# ATLAS Guardian Backup — ${today}`,
      ``,
      `## Summary`,
      `- **Status:** ${allSuccess ? "✅ All tables backed up" : "⚠️ Some tables failed"}`,
      `- **Tables:** ${successCount}/${BACKUP_TABLES.length} successful`,
      `- **Total rows:** ${totalRows.toLocaleString()}`,
      `- **Total size:** ${Math.round(totalSizeBytes / 1024)} KB`,
      `- **Completed:** ${new Date().toUTCString()}`,
      `- **Manifest checksum:** ${manifestChecksum.slice(0, 32)}`,
      ``,
      `## Tables`,
      ...tableResults.map(t =>
        `- ${t.success ? "✅" : "❌"} \`${t.name}\` — ${t.rows} rows${t.error ? ` (${t.error})` : ""}`
      ),
    ].join("\n");

    await pushToGitHub(
      `backups/${today}/summary.md`,
      summaryLines,
      `Guardian backup ${today} — summary`
    );

    const githubUrl = `https://github.com/${GITHUB_REPO}/tree/main/backups/${today}`;
    const durationMs = Date.now() - startMs;

    await sb.from("guardian_manifests").update({
      tables_backed:   tableResults,
      total_rows:      totalRows,
      file_size_bytes: totalSizeBytes,
      checksum:        manifestChecksum,
      status:          allSuccess ? "completed" : "failed",
      github_url:      githubUrl,
      completed_at:    new Date().toISOString(),
    }).eq("id", manifestId);

    await sb.from("guardian_reports").update({
      backup_status:   allSuccess ? "completed" : "failed",
      backup_location: githubUrl,
      updated_at:      new Date().toISOString(),
    }).eq("report_date", today);

    if (!allSuccess) {
      const failedTables = tableResults.filter(t => !t.success).map(t => t.name);
      await sb.from("guardian_alerts").insert({
        alert_type: "backup.failed",
        severity:   "critical",
        message:    `Backup partially failed. Tables: ${failedTables.join(", ")}`,
        metadata:   { failed_tables: failedTables, github_url: githubUrl },
        status:     "active",
      });
    } else {
      await sb.from("guardian_alerts")
        .update({ status: "resolved", resolved_at: new Date().toISOString() })
        .eq("alert_type", "backup.failed")
        .eq("status", "active");

      await sb.from("guardian_alerts")
        .update({ status: "resolved", resolved_at: new Date().toISOString() })
        .eq("alert_type", "backup.overdue")
        .eq("status", "active");
    }

    // ── Atlas Event Log — permanent record of this backup ──────
    sb.rpc("log_atlas_event", {
      p_event_type: "guardian.backup.completed",
      p_entity_key: "guardian",
      p_payload: {
        success: allSuccess,
        tables_backed: successCount,
        total_rows: totalRows,
        size_kb: Math.round(totalSizeBytes / 1024),
        duration_ms: durationMs,
      },
    }).then(() => {}).catch((e: Error) => log("warn", "event_log_failed", { error: e.message }));

    log("info", "backup_completed", {
      allSuccess, totalRows, totalSizeBytes,
      tables: BACKUP_TABLES.length,
      durationMs, githubUrl,
    });

    return new Response(JSON.stringify({
      success:      allSuccess,
      tables_backed: successCount,
      tables_failed: failCount,
      total_rows:   totalRows,
      size_kb:      Math.round(totalSizeBytes / 1024),
      github_url:   githubUrl,
      duration_ms:  durationMs,
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log("error", "backup_failed", { error: msg });

    await sb.from("guardian_manifests").update({
      status:        "failed",
      error_message: msg,
      completed_at:  new Date().toISOString(),
    }).eq("id", manifestId);

    await sb.from("guardian_alerts").insert({
      alert_type: "backup.failed",
      severity:   "critical",
      message:    `Backup failed: ${msg}`,
      metadata:   { error: msg },
      status:     "active",
    }).catch(() => {});

    return new Response(JSON.stringify({ success: false, error: msg }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
