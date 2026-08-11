// gcal-broker — Supabase Edge Function
// Holds Google refresh tokens server-side and mints fresh access tokens
// for the This Week app, so calendar sync never needs a login prompt.
// Paste this whole file into Supabase → Edge Functions → new function "gcal-broker".
// Requires two function secrets: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET.
// Contains no secrets itself.

import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

function json(obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, "content-type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  try {
    const supa = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );
    const jwt = (req.headers.get("Authorization") || "").replace("Bearer ", "");
    const { data: userData, error: uerr } = await supa.auth.getUser(jwt);
    if (uerr || !userData?.user) return json({ error: "not signed in to sync" }, 401);
    const uid = userData.user.id;

    const body = await req.json();
    const cid = Deno.env.get("GOOGLE_CLIENT_ID");
    const csec = Deno.env.get("GOOGLE_CLIENT_SECRET");
    if (!cid || !csec) return json({ error: "broker secrets not set" }, 500);

    if (body.action === "exchange") {
      // one-time: swap the consent code for tokens, keep the refresh token
      const r = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code: body.code,
          client_id: cid,
          client_secret: csec,
          redirect_uri: body.redirect_uri,
          grant_type: "authorization_code",
        }),
      });
      const tok = await r.json();
      if (!tok.access_token) {
        return json(
          { error: tok.error_description || tok.error || "exchange failed" },
          400,
        );
      }
      const ui = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: { Authorization: "Bearer " + tok.access_token },
      });
      const info = await ui.json();
      const email = info.email || "(unknown)";
      if (tok.refresh_token) {
        await supa.from("gcal_tokens").upsert({
          user_id: uid,
          email,
          refresh_token: tok.refresh_token,
          updated_at: new Date().toISOString(),
        });
      }
      return json({
        email,
        access_token: tok.access_token,
        expires_in: tok.expires_in,
      });
    }

    if (body.action === "token") {
      // routine: mint a fresh access token from the stored refresh token
      const { data: row } = await supa
        .from("gcal_tokens")
        .select("refresh_token")
        .eq("user_id", uid)
        .eq("email", body.email)
        .maybeSingle();
      if (!row) return json({ error: "no saved connection — connect this account again" }, 410);
      const r = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          refresh_token: row.refresh_token,
          client_id: cid,
          client_secret: csec,
          grant_type: "refresh_token",
        }),
      });
      const tok = await r.json();
      if (!tok.access_token) {
        if (tok.error === "invalid_grant") {
          await supa.from("gcal_tokens").delete().eq("user_id", uid).eq("email", body.email);
          return json({ error: "connection expired — connect this account again" }, 410);
        }
        return json(
          { error: tok.error_description || tok.error || "refresh failed" },
          400,
        );
      }
      return json({ access_token: tok.access_token, expires_in: tok.expires_in });
    }

    if (body.action === "list") {
      const { data } = await supa
        .from("gcal_tokens")
        .select("email")
        .eq("user_id", uid);
      return json({ emails: (data || []).map((r: { email: string }) => r.email) });
    }

    if (body.action === "remove") {
      await supa.from("gcal_tokens").delete().eq("user_id", uid).eq("email", body.email);
      return json({ ok: true });
    }

    return json({ error: "unknown action" }, 400);
  } catch (e) {
    return json({ error: String((e as Error)?.message || e) }, 500);
  }
});
