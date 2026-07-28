// ============================================================
// ATLAS AABOS — Guardian Health Monitor v1.2
// supabase/functions/guardian-health/index.ts
//
// Runs nightly at 01:00 via pg_cron
// Scans all Atlas tables, calculates Guardian Score,
// stores health report, raises alerts on anomalies
//
// v1.1: Added CORS headers — required for browser calls
// v1.2: Self-registers in atlas_registry, sweeps stale entities
// v1.3: Logs guardian.scan.completed to the Atlas Event Log
// ============================================================

import { serve }        from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")    ?? "";
const SUPABASE_SVC = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
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

const MONITORED_TABLES = [
  "businesses", "tasks", "revenue_logs", "expenses",
  "affiliate_links", "content_queue", "knowledge",
  "trends", "subscriptions", "plans",
  "guardian_reports", "guardian_alerts", "guardian_manifests",
  "audit_logs", "security_events", "agent_runs", "agent_tasks"
];

const ROW_DROP_THRESHOLD = 0.10;

const SCORE_WEIGHTS = {
  tables_healthy:  40,
  backup_recent:   35,
  cron_active:     15,
  no_critical:     10,
};

interface TableHealth {
  name:       string;
  rows:       number;
  prev_rows:  number;
  drop_pct:   number;
  healthy:    boolean;
}

function log(level: string, event: string, meta: Record<string, unknown> = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    level, event,
    service: "guardian-health",
    ...meta
  }));
}

async function getRowCount(
  sb: ReturnType<typeof createClient>,
  table: string
): Promise<number> {
  try {
    const { count, error } = await sb
      .from(table)
      .select("*", { count: "exact", head: true });
    if (error) return -1;
    return count ?? 0;
  } catch {
    return -1;
  }
}

async function getPreviousCounts(
  sb: ReturnType<typeof createClient>
): Promise<Record<string, number>> {
  const { data } = await sb
    .from("guardian_reports")
    .select("findings")
    .order("report_date", { ascending: false })
    .limit(1)
    .single();

  if (!data?.findings?.table_counts) return {};
  return data.findings.table_counts as Record<string, number>;
}

async function raiseAlert(
  sb: ReturnType<typeof createClient>,
  alertType: string,
  severity: "info" | "warning" | "critical",
  message: string,
  metadata: Record<string, unknown> = {}
): Promise<void> {
  const { data: existing } = await sb
    .from("guardian_alerts")
    .select("id")
    .eq("alert_type", alertType)
    .eq("status", "active")
    .limit(1);

  if (existing && existing.length > 0) return;

  await sb.from("guardian_alerts").insert({
    alert_type: alertType,
    severity,
    message,
    metadata,
    status: "active",
  });

  log("warn", "alert_raised", { alertType, severity, message });
}

async function resolveAlert(
  sb: ReturnType<typeof createClient>,
  alertType: string
): Promise<void> {
  await sb
    .from("guardian_alerts")
    .update({ status: "resolved", resolved_at: new Date().toISOString() })
    .eq("alert_type", alertType)
    .eq("status", "active");
}

// ── Main handler ──────────────────────────────────────────────
serve(async (req: Request) => {
  const origin      = req.headers.get("origin");
  const corsHeaders = buildCorsHeaders(origin);

  // Handle preflight — THIS WAS MISSING IN v1.0
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const startMs = Date.now();
  log("info", "health_scan_started");

  if (!SUPABASE_URL || !SUPABASE_SVC) {
    log("error", "missing_env_vars");
    return new Response(JSON.stringify({ error: "Missing environment variables" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  const sb = createClient(SUPABASE_URL, SUPABASE_SVC);

  try {
    const prevCounts = await getPreviousCounts(sb);
    log("info", "prev_counts_loaded", { tables: Object.keys(prevCounts).length });

    const tableHealth: TableHealth[] = [];
    const currentCounts: Record<string, number> = {};
    let totalRows = 0;

    for (const table of MONITORED_TABLES) {
      const rows     = await getRowCount(sb, table);
      const prevRows = prevCounts[table] ?? rows;
      const dropPct  = prevRows > 0
        ? Math.max(0, (prevRows - rows) / prevRows)
        : 0;
      const healthy  = rows >= 0 && dropPct < ROW_DROP_THRESHOLD;

      currentCounts[table] = rows >= 0 ? rows : 0;
      if (rows >= 0) totalRows += rows;

      tableHealth.push({ name: table, rows, prev_rows: prevRows, drop_pct: dropPct, healthy });

      if (!healthy && rows >= 0) {
        await raiseAlert(sb,
          `table.row.drop.${table}`, "critical",
          `Table ${table} lost ${Math.round(dropPct * 100)}% of rows (${prevRows} → ${rows})`,
          { table, prev_rows: prevRows, current_rows: rows, drop_pct: dropPct }
        );
      } else {
        await resolveAlert(sb, `table.row.drop.${table}`);
      }
    }

    const tablesHealthy = tableHealth.filter(t => t.healthy).length;

    log("info", "tables_scanned", {
      total: MONITORED_TABLES.length,
      healthy: tablesHealthy,
      total_rows: totalRows
    });

    const { data: lastBackup } = await sb
      .from("guardian_manifests")
      .select("completed_at, status, github_url")
      .eq("status", "completed")
      .order("completed_at", { ascending: false })
      .limit(1)
      .single();

    const backupAgeHours = lastBackup?.completed_at
      ? (Date.now() - new Date(lastBackup.completed_at).getTime()) / 3600000
      : 999;
    const backupRecent = backupAgeHours < 25;

    if (!backupRecent) {
      await raiseAlert(sb, "backup.overdue", "critical",
        `No successful backup in ${Math.round(backupAgeHours)} hours. Last backup: ${lastBackup?.completed_at ?? "never"}`,
        { backup_age_hours: backupAgeHours }
      );
    } else {
      await resolveAlert(sb, "backup.overdue");
    }

    const expectedCrons = [
      "atlas-kpi-snapshot", "atlas-rl-cleanup",
      "atlas-guardian-health", "atlas-guardian-backup"
    ];

    let activeCronNames: string[] = [];
    try {
      const { data: cronJobs } = await sb
        .from("cron.job" as never)
        .select("jobname, active")
        .like("jobname", "atlas-%");
      activeCronNames = ((cronJobs ?? []) as Array<{jobname: string; active: boolean}>)
        .filter(j => j.active)
        .map(j => j.jobname);
    } catch {
      activeCronNames = [];
    }

    const missingCrons = expectedCrons.filter(c => !activeCronNames.includes(c));

    for (const missing of missingCrons) {
      await raiseAlert(sb, `cron.missing.${missing}`, "warning",
        `Expected cron job not found: ${missing}`,
        { jobname: missing }
      );
    }
    for (const found of expectedCrons.filter(c => activeCronNames.includes(c))) {
      await resolveAlert(sb, `cron.missing.${found}`);
    }

    const { count: criticalCount } = await sb
      .from("guardian_alerts")
      .select("*", { count: "exact", head: true })
      .eq("status", "active")
      .eq("severity", "critical");

    const activeCriticals = criticalCount ?? 0;

    let score = 0;
    const tableHealthRatio = tablesHealthy / MONITORED_TABLES.length;
    score += Math.round(SCORE_WEIGHTS.tables_healthy * tableHealthRatio);
    if (backupRecent) score += SCORE_WEIGHTS.backup_recent;
    const cronRatio = expectedCrons.length > 0
      ? (expectedCrons.length - missingCrons.length) / expectedCrons.length
      : 1;
    score += Math.round(SCORE_WEIGHTS.cron_active * cronRatio);
    if (activeCriticals === 0) score += SCORE_WEIGHTS.no_critical;
    score = Math.min(100, Math.max(0, score));

    const status = score >= 90 ? "healthy" : score >= 70 ? "warning" : "critical";

    log("info", "score_calculated", { score, status, activeCriticals });

    if (score < 60) {
      await raiseAlert(sb, "score.critical", "critical",
        `Guardian Score is critically low: ${score}/100`, { score }
      );
    } else if (score < 80) {
      await raiseAlert(sb, "score.degraded", "warning",
        `Guardian Score is degraded: ${score}/100`, { score }
      );
      await resolveAlert(sb, "score.critical");
    } else {
      await resolveAlert(sb, "score.degraded");
      await resolveAlert(sb, "score.critical");
    }

    const findings = {
      table_counts:      currentCounts,
      table_health:      tableHealth,
      backup_age_hours:  Math.round(backupAgeHours * 10) / 10,
      backup_recent:     backupRecent,
      last_backup_url:   lastBackup?.github_url ?? null,
      missing_crons:     missingCrons,
      active_criticals:  activeCriticals,
      scan_duration_ms:  Date.now() - startMs,
    };

    await sb.from("guardian_reports").upsert({
      report_date:    new Date().toISOString().split("T")[0],
      guardian_score: score,
      status,
      tables_checked: MONITORED_TABLES.length,
      total_rows:     totalRows,
      backup_status:  backupRecent ? "completed" : "overdue",
      backup_location: lastBackup?.github_url ?? null,
      findings,
      updated_at:     new Date().toISOString(),
    }, { onConflict: "report_date" });

    // ── Agent Registry — self-register + sweep stale entities ──
    // Fire-and-forget: registry housekeeping never blocks the health scan
    sb.rpc("heartbeat_atlas_entity", {
      p_entity_key: "guardian",
      p_status: status === "critical" ? "degraded" : "online",
    }).then(() => {}).catch((e: Error) => log("warn", "registry_heartbeat_failed", { error: e.message }));

    sb.rpc("heartbeat_atlas_entity", {
      p_entity_key: "guardian-health",
      p_status: "online",
    }).then(() => {}).catch(() => {});

    sb.rpc("mark_stale_registry_entities")
      .then((res: { data: number | null }) => {
        if (res.data && res.data > 0) {
          log("info", "registry_swept", { entities_marked_stale: res.data });
        }
      })
      .catch((e: Error) => log("warn", "registry_sweep_failed", { error: e.message }));

    // ── Atlas Event Log — permanent record of this scan ────────
    sb.rpc("log_atlas_event", {
      p_event_type: "guardian.scan.completed",
      p_entity_key: "guardian",
      p_payload: {
        score, status,
        tables_checked: MONITORED_TABLES.length,
        total_rows: totalRows,
        active_alerts: activeCriticals,
      },
    }).then(() => {}).catch((e: Error) => log("warn", "event_log_failed", { error: e.message }));

    log("info", "health_scan_completed", {
      score, status,
      duration_ms: Date.now() - startMs,
      total_rows:  totalRows,
      tables:      MONITORED_TABLES.length,
    });

    return new Response(JSON.stringify({
      success:       true,
      guardian_score: score,
      status,
      tables_checked: MONITORED_TABLES.length,
      total_rows:    totalRows,
      backup_recent: backupRecent,
      active_alerts: activeCriticals,
      duration_ms:   Date.now() - startMs,
    }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });

  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log("error", "health_scan_failed", { error: msg });

    await sb.from("guardian_reports").upsert({
      report_date:    new Date().toISOString().split("T")[0],
      guardian_score: 0,
      status:         "critical",
      findings:       { error: msg },
      updated_at:     new Date().toISOString(),
    }, { onConflict: "report_date" }).catch(() => {});

    sb.rpc("heartbeat_atlas_entity", {
      p_entity_key: "guardian",
      p_status: "degraded",
    }).then(() => {}).catch(() => {});

    return new Response(JSON.stringify({ success: false, error: msg }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
