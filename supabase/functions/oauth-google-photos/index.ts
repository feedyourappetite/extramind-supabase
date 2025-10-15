import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const ALLOWED_ORIGINS: (string | RegExp)[] = [
  'http://localhost:5173',
  'https://localhost:5173',
  /\.webcontainer-api\.io$/i,
  /\.stackblitz\.io$/i,
  /\.stackblitz\.com$/i,
];

function computeAllowOrigin(origin?: string | null) {
  if (!origin) return '*';
  for (const rule of ALLOWED_ORIGINS) {
    if (typeof rule === 'string' ? origin === rule : rule.test(origin)) return origin;
  }
  return '*';
}

function corsHeaders(req: Request) {
  const origin = req.headers.get('origin');
  const allow = computeAllowOrigin(origin);
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers':
      'Content-Type, Authorization, apikey, x-client-info, x-supabase-auth',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function j(req: Request, body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
  });
}

function h(req: Request, html: string, status = 200) {
  return new Response(html, {
    status,
    headers: { ...corsHeaders(req), 'Content-Type': 'text/html' },
  });
}

function err(req: Request, status: number, message: string, extra?: Record<string, unknown>) {
  const payload: any = { code: status, message, error: message, ...(extra && { debug: extra }) };
  return new Response(JSON.stringify(payload), {
    status,
    headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
  });
}

const CLIENT_ID = Deno.env.get("GOOGLE_CLIENT_ID");
const CLIENT_SECRET = Deno.env.get("GOOGLE_CLIENT_SECRET");
const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

const SCOPES = [
  "https://www.googleapis.com/auth/photoslibrary.readonly",
  "https://www.googleapis.com/auth/photoslibrary.sharing",
];

Deno.serve(async (req) => {
  try {
    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(req) });
    }

    const url = new URL(req.url);
    console.log('[CORS]', {
      method: req.method,
      origin: req.headers.get('origin'),
      allow: corsHeaders(req)['Access-Control-Allow-Origin'],
      path: url.pathname,
    });

    if (!CLIENT_ID || !CLIENT_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      return err(req, 500, "Server misconfigured: missing OAuth credentials");
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    if (req.method === 'POST') {
      let body: any = {};
      try {
        body = await req.json();
      } catch {
        return err(req, 400, "Invalid JSON body");
      }

            const authHeader = req.headers.get("authorization");
      if (!authHeader) {
        return err(req, 401, "Missing authorization header");
      }

      const token = authHeader.replace(/^Bearer\s+/i, "");

      // Verify JWT and extract user_id
      let userId: string;
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        userId = payload.sub;
        if (!userId) {
          return err(req, 401, "Invalid token: missing sub claim");
        }
      } catch (e) {
        return err(req, 401, "Invalid token format");
      }

     const returnTo = body.return_to || "http://localhost:5173";
      const albumHint = body.album_hint || "";

      const state = btoa(JSON.stringify({
        user_id: userId,
        return_to: returnTo,
        album_hint: albumHint
      }));

      const redirectUri = `${url.origin}${url.pathname}`;

      const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      authUrl.searchParams.set("client_id", CLIENT_ID);
      authUrl.searchParams.set("redirect_uri", redirectUri);
      authUrl.searchParams.set("response_type", "code");
      authUrl.searchParams.set("scope", SCOPES.join(" "));
      authUrl.searchParams.set("access_type", "offline");
      authUrl.searchParams.set("prompt", "consent");
      authUrl.searchParams.set("state", state);

      return j(req, { auth_url: authUrl.toString() });
    }

    if (req.method === 'GET') {
      const code = url.searchParams.get("code");
      const stateParam = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error) {
        return h(req, `
          <!DOCTYPE html>
          <html>
            <head><title>Authorization Failed</title></head>
            <body>
              <h1>Authorization Failed</h1>
              <p>Error: ${error}</p>
              <p><a href="http://localhost:5173">Return to app</a></p>
            </body>
          </html>
        `, 400);
      }

      if (!code || !stateParam) {
        return err(req, 400, "Missing code or state parameter");
      }

      let state: any;
      try {
        state = JSON.parse(atob(stateParam));
      } catch {
        return err(req, 400, "Invalid state parameter");
      }

      const redirectUri = `${url.origin}${url.pathname}`;

      const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          redirect_uri: redirectUri,
          grant_type: "authorization_code",
        }),
      });

      if (!tokenResponse.ok) {
        const errorText = await tokenResponse.text();
        return err(req, 502, "Failed to exchange code for token", { error: errorText });
      }

      const tokens = await tokenResponse.json();

      const { error: upsertError } = await supabase
        .from("google_oauth")
        .upsert({
          user_id: state.user_id,
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          expires_at: new Date(Date.now() + tokens.expires_in * 1000).toISOString(),
          scope: tokens.scope,
          token_type: tokens.token_type,
        });

      if (upsertError) {
        return err(req, 500, "Failed to store tokens", { error: upsertError.message });
      }

      const returnTo = state.return_to || "http://localhost:5173";
      const successHtml = `
        <!DOCTYPE html>
        <html>
          <head>
            <title>Authorization Successful</title>
            <style>
              body {
                font-family: system-ui, -apple-system, sans-serif;
                max-width: 600px;
                margin: 40px auto;
                padding: 20px;
                text-align: center;
              }
              .success { color: #16a34a; }
              button {
                background: #2563eb;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-size: 16px;
                cursor: pointer;
                margin-top: 20px;
              }
              button:hover { background: #1d4ed8; }
            </style>
          </head>
          <body>
            <h1 class="success">✓ Authorization Successful</h1>
            <p>Your Google Photos account has been linked.</p>
            <button onclick="window.location.href='${returnTo}'">Return to App</button>
          </body>
        </html>
      `;

      return h(req, successHtml);
    }

    return err(req, 405, "Method Not Allowed");

  } catch (e: any) {
    console.error('[EDGE ERROR]', e?.stack || e);
    return err(req, 500, 'Internal Server Error');
  }
});
