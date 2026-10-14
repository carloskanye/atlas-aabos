// ============================================================
// ATLAS AABOS — Real Agent Scheduler (OpenAI)
// supabase/functions/agent-scheduler/index.ts
//
// Provider: OpenAI (gpt-4o)
// All Anthropic references removed.
//
// Deploy: supabase functions deploy agent-scheduler
// Trigger: pg_cron calls this every 5 minutes
// ============================================================

import { serve }        from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "*";

// ── OpenAI response types ─────────────────────────────────────
interface OpenAIResponse {
  choices: Array<{ message: { content: string } }>;
  usage:   { prompt_tokens: number; completion_tokens: number };
}

// ── Agent prompts — return JSON only ─────────────────────────
// Using response_format: json_object on gpt-4o guarantees valid JSON output.
// Each prompt instructs the model to return a specific schema.
const AGENT_PROMPTS: Record<string, (input: Record<string, unknown>) => string> = {
  "Trend Agent": (input) => `
    You are Atlas's Trend Agent running an automated morning scan.
    Today's date: ${new Date().toDateString()}.
    ${input.focus ? `Focus area: ${input.focus}` : ""}
    Analyze current Pinterest and social media trends for: fashion, streetwear, fragrance, luxury accessories, entrepreneurship.
    Return a JSON object matching this exact schema:
    {
      "trends": [{"category": string, "score": number (0-100), "tag": string, "insight": string, "content_angle": string}],
      "top_opportunity": string,
      "recommended_action": string
    }`,

  "Content Agent": (input) => `
    You are Atlas's Content Agent running automated content generation.
    Business: ${input.business ?? "all businesses"}
    Theme: ${input.theme ?? "weekly content"}
    Generate a content batch. Return a JSON object matching this exact schema:
    {
      "items": [{"type": string, "business": string, "copy": string}],
      "summary": string
    }
    Valid types: "Pinterest Pin", "Instagram Post", "X Post", "Blog Title"`,

  "Analytics Agent": (_input) => `
    You are Atlas's Analytics Agent generating a weekly performance report.
    Today: ${new Date().toDateString()}.
    Context: South African entrepreneur running ThriftVerse (streetwear marketplace), Atlas Noir (luxury belts), a fragrance brand (in development), and affiliate marketing.
    Return a JSON object matching this exact schema:
    {
      "key_insights": [string],
      "actions": [{"priority": string, "action": string, "expected_impact": string}],
      "weekly_focus": string
    }
    Valid priorities: "high", "medium", "low"`,

  "Research Agent": (input) => `
    You are Atlas's Research Agent.
    Research topic: ${input.topic ?? "luxury streetwear accessories market South Africa"}
    Return a JSON object matching this exact schema:
    {
      "findings": [string],
      "opportunities": [{"title": string, "description": string, "urgency": string}],
      "competitors": [{"name": string, "weakness": string}],
      "recommended_move": string
    }
    Valid urgency values: "high", "medium", "low"`,

  "Brain Agent": (_input) => `
    You are Atlas's Brain Agent — strategic synthesis across all businesses.
    Today: ${new Date().toDateString()}.
    Businesses: ThriftVerse (marketplace), Atlas Noir (luxury belts), Fragrance Brand (in development), Affiliate Engine.
    Return a JSON object matching this exact schema:
    {
      "strategic_priorities": [{"rank": number, "priority": string, "rationale": string}],
      "risks": [string],
      "this_week_focus": string,
      "one_insight": string
    }`,
};

// ── Call OpenAI ───────────────────────────────────────────────
// Returns reply text + token counts.
// Uses response_format: json_object for agent calls (guarantees valid JSON).
async function callOpenAI(
  systemPrompt: string,
  userPrompt:   string,
  maxTokens = 1500,
  jsonMode  = true
): Promise<{ reply: string; inputTokens: number; outputTokens: number }> {
  const apiKey = Deno.env.get("OPENAI_API_KEY");
  if (!apiKey) throw new Error("OPENAI_API_KEY not set");

  const body: Record<string, unknown> = {
    model:      "llama-3.3-70b-versatile",
    max_tokens: maxTokens,
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user",   content: userPrompt   },
    ],
  };

  // json_object mode forces valid JSON — eliminates parsing failures
  if (jsonMode) {
    body.response_format = { type: "json_object" };
  }

  const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type":  "application/json",
      "Authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const errText = await resp.text();
    throw new Error(`Groq ${resp.status}: ${errText}`);
  }

  const data: OpenAIResponse = await resp.json();
  return {
    reply:        data.choices?.[0]?.message?.content ?? "",
    inputTokens:  data.usage?.prompt_tokens     ?? 0,
    outputTokens: data.usage?.completion_tokens ?? 0,
  };
}

// ── Persist agent results to AABOS tables ────────────────────
async function persistResults(
  supabase:  ReturnType<typeof createClient>,
  userId:    string,
  agentName: string,
  parsed:    Record<string, unknown>
): Promise<void> {
  // Trend Agent → trends table
  if (agentName === "Trend Agent" && Array.isArray(parsed.trends)) {
    const rows = (parsed.trends as Array<Record<string, unknown>>).map(t => ({
      user_id:  userId,
      category: String(t.category ?? "UNKNOWN").toUpperCase(),
      score:    Math.min(100, Math.max(0, Number(t.score ?? 50))),
      tag:      String(t.tag ?? "📊 STABLE"),
      source:   "Trend Agent (automated)",
    }));
    const { error } = await supabase.from("trends").insert(rows);
    if (error) throw new Error(`trends insert failed: ${error.message}`);
  }

  // Content Agent → content_queue
  if (agentName === "Content Agent" && Array.isArray(parsed.items)) {
    const rows = (parsed.items as Array<Record<string, unknown>>).map(item => ({
      user_id:  userId,
      type:     String(item.type     ?? "Post"),
      business: String(item.business ?? ""),
      body:     String(item.copy     ?? ""),
      status:   "Draft",
      platform: String(item.type ?? "").toLowerCase().includes("pin") ? "Pinterest" : "Social",
    }));
    const { error } = await supabase.from("content_queue").insert(rows);
    if (error) throw new Error(`content_queue insert failed: ${error.message}`);
  }

  // Research / Brain / Analytics → knowledge vault
  if (["Research Agent", "Brain Agent", "Analytics Agent"].includes(agentName)) {
    const summary  = parsed.recommended_move ?? parsed.this_week_focus ?? parsed.weekly_focus ?? "Agent run complete";
    const insights = parsed.findings ?? parsed.strategic_priorities ?? parsed.key_insights ?? [];
    const { error } = await supabase.from("knowledge").insert({
      user_id:  userId,
      title:    `${agentName} Report — ${new Date().toLocaleDateString("en-ZA")}`,
      category: "Business",
      content:  `${summary}\n\nDetails:\n${JSON.stringify(insights, null, 2)}`,
      tags:     [agentName, "automated", new Date().toLocaleDateString("en-ZA")],
    });
    if (error) throw new Error(`knowledge insert failed: ${error.message}`);
  }
}

// ── Checked task completion ──────────────────────────────────
async function completeAgentTask(
  supabase: ReturnType<typeof createClient>,
  params: { p_task_id: string; p_status: string; p_output?: Record<string, unknown>; p_error?: string }
): Promise<void> {
  const { error } = await supabase.rpc("complete_agent_task", params);
  if (error) throw new Error(`complete_agent_task failed: ${error.message}`);
}

// ── Main handler ─────────────────────────────────────────────
serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: { "Access-Control-Allow-Origin": ALLOWED_ORIGIN } });
  }

  // Called by trusted automation with a service-role credential in Authorization.
  const authHeader = req.headers.get("Authorization") ?? "";
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

  let authorizedServiceCredential = !!serviceKey && authHeader === `Bearer ${serviceKey}`;
  if (!authorizedServiceCredential && supabaseUrl && anonKey && authHeader.startsWith("Bearer ")) {
    // Validate effective DB privileges to support key rotation between Vault and
    // function environment. guardian_operators is not readable by anon/authenticated.
    const verifier = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { error: verifyError } = await verifier
      .from("guardian_operators")
      .select("user_id")
      .limit(0);
    authorizedServiceCredential = !verifyError;
  }

  if (!authorizedServiceCredential || !supabaseUrl || !serviceKey) {
    return new Response(JSON.stringify({ error: "Forbidden" }), { status: 403 });
  }

  const supabase = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  const results: Array<Record<string, unknown>> = [];
  let claimFailure: string | null = null;
  const MAX_TASKS_PER_RUN = 3;

  for (let i = 0; i < MAX_TASKS_PER_RUN; i++) {
    // Claim next pending task atomically (SKIP LOCKED)
    const { data: task, error: claimErr } = await supabase.rpc("claim_next_agent_task");
    if (claimErr) {
      claimFailure = claimErr.message;
      console.error("[agent-scheduler] claim_next_agent_task failed:", claimErr.message);
      break;
    }
    if (!task?.id) break;

    const taskId    = task.id        as string;
    const userId    = task.user_id   as string;
    const agentName = task.agent_name as string;
    const input     = (task.input ?? {}) as Record<string, unknown>;
    const startedAt = new Date().toISOString();
    const startMs   = Date.now();

    console.log(`[agent-scheduler] Running ${agentName} for user ${userId.slice(0, 8)}…`);

    try {
      // Check plan allows agents
      const { data: limits, error: limitsErr } = await supabase.rpc("get_user_plan_limits", { p_user_id: userId });
      if (limitsErr) throw new Error(`get_user_plan_limits failed: ${limitsErr.message}`);
      if (!limits?.agents_enabled) {
        await completeAgentTask(supabase,
          p_task_id: taskId, p_status: "failed",
          p_error:   "Agents not available on current plan. Upgrade to Pro.",
        });
        results.push({ taskId, status: "plan_blocked", agentName });
        continue;
      }

      // Get agent prompt function
      const promptFn = AGENT_PROMPTS[agentName];
      if (!promptFn) {
        await completeAgentTask(supabase, {
          p_task_id: taskId, p_status: "failed",
          p_error:   `Unknown agent: ${agentName}`,
        });
        results.push({ taskId, status: "failed", agentName, error: `Unknown agent: ${agentName}` });
        continue;
      }

      const userPrompt   = promptFn(input);
      const systemPrompt = "You are ATLAS, an AI Business Operating System. Return valid JSON only.";

      // Call OpenAI with json_object mode
      const { reply: rawReply, inputTokens, outputTokens } = await callOpenAI(
        systemPrompt, userPrompt, 1500, true
      );

      // Parse JSON — json_object mode makes this reliable
      let parsed: Record<string, unknown> = {};
      try {
        parsed = JSON.parse(rawReply);
      } catch {
        // Fallback: strip any accidental markdown fences and retry
        try {
          parsed = JSON.parse(rawReply.replace(/```json\n?|```\n?/g, "").trim());
        } catch {
          parsed = { raw_output: rawReply };
        }
      }

      // Persist business output; any failure prevents a successful task state.
      await persistResults(supabase, userId, agentName, parsed);

      // Mark task complete and surface RPC failures.
      await completeAgentTask(supabase, {
        p_task_id: taskId, p_status: "success", p_output: parsed,
      });

      // Run logging is observability: report a logging failure without retrying
      // a task whose business output and task completion already succeeded.
      const { error: runLogError } = await supabase.from("agent_runs").insert({
        user_id:       userId,
        agent_name:    agentName,
        status:        "success",
        prompt:        userPrompt.slice(0, 500),
        result:        rawReply.slice(0, 500),
        tokens_used:   inputTokens + outputTokens,
        input_tokens:  inputTokens,
        output_tokens: outputTokens,
        duration_ms:   Date.now() - startMs,
        created_at:    startedAt,
        completed_at:  new Date().toISOString(),
      });
      if (runLogError) {
        console.error("[agent-scheduler] agent_runs success log failed:", runLogError.message);
        results.push({ taskId, status: "success", agentName, inputTokens, outputTokens, warning: "agent_runs logging failed" });
      } else {
        results.push({ taskId, status: "success", agentName, inputTokens, outputTokens });
      }

    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error(`[agent-scheduler] ${agentName} failed:`, errMsg);

      let completionFailure: string | null = null;
      try {
        await completeAgentTask(supabase, {
          p_task_id: taskId, p_status: "failed", p_error: errMsg,
        });
      } catch (completionErr) {
        completionFailure = completionErr instanceof Error ? completionErr.message : String(completionErr);
        console.error("[agent-scheduler] failed to mark task failed:", completionFailure);
      }

      const { error: failedRunLogError } = await supabase.from("agent_runs").insert({
        user_id:      userId,
        agent_name:   agentName,
        status:       "failed",
        prompt:       "",
        result:       "",
        error:        errMsg,
        duration_ms:  Date.now() - startMs,
        created_at:   startedAt,
        completed_at: new Date().toISOString(),
      });
      if (failedRunLogError) console.error("[agent-scheduler] failed to insert failure run log:", failedRunLogError.message);

      results.push({ taskId, status: "failed", agentName, error: errMsg, ...(completionFailure ? { completionError: completionFailure } : {}) });
    }
  }

  return new Response(
    JSON.stringify({ processed: results.length, results, ...(claimFailure ? { error: "Task claim failed" } : {}) }),
    { status: claimFailure ? 500 : 200, headers: { "Content-Type": "application/json" } }
  );
});
