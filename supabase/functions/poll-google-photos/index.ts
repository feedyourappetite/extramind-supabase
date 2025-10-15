import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const DEBUG = Deno.env.get("DEBUG") === "1";

const ALLOWED_ORIGINS: (string | RegExp)[] = [
  "http://localhost:5173",
  "https://localhost:5173",
  "http://127.0.0.1:5173",
  "https://127.0.0.1:5173",
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

function getCorsHeaders(req: Request) {
  const origin = req.headers.get("origin");
  const allow = computeAllowOrigin(origin);
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, apikey, x-client-info, x-supabase-auth",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

const PHOTOS_API = "https://photoslibrary.googleapis.com/v1/mediaItems:search";
const TOKEN_URL = "https://oauth2.googleapis.com/token";

function env(name: string, fallback?: string): string {
  const v = Deno.env.get(name) ?? fallback;
  if (v === undefined) throw new Error(`Missing env: ${name}`);
  return v;
}

function parseAllowedAlbumUrls(): string[] {
  const raw = Deno.env.get("PHOTOS_ALLOWED_ALBUMS")?.trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => {
      try { return new URL(s).toString(); } catch { return s; }
    });
}

function normalizeAlbumUrl(url?: string): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    u.pathname = u.pathname.replace(/\/+$/, "");
    return u.toString();
  } catch {
    return undefined;
  }
}

function extractAlbumId(s: string): string {
  s = s.trim();
  if (!s) return "";
  if (s.startsWith("http")) {
    try {
      const u = new URL(s);
      const parts = u.pathname.split("/").filter(Boolean);
      const i = parts.findIndex(p => p === "album" || p === "share");
      if (i >= 0 && parts[i + 1]) return parts[i + 1];
    } catch {}
  }
  return s;
}

const MAX_ITEMS_PER_RUN = 50;
const MAX_PAGES_PER_RUN = 1;
const ALLOWED_MIME = ["image/jpeg", "image/png", "image/webp"];
const ALLOWED_ALBUMS = parseAllowedAlbumUrls();

const CLIENT_ID = Deno.env.get("GOOGLE_CLIENT_ID")!;
const CLIENT_SECRET = Deno.env.get("GOOGLE_CLIENT_SECRET")!;
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const supabaseKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

function bad(req: Request, status: number, message: string) {
  return new Response(JSON.stringify({ code: status, message }), {
    status,
    headers: { ...getCorsHeaders(req), "content-type": "application/json" },
  });
}

function json(req: Request, obj: unknown, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...getCorsHeaders(req), "content-type": "application/json" },
  });
}

async function getAuthUser(req: Request): Promise<{ id: string } | null> {
  const auth = req.headers.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  try {
    const payload = JSON.parse(atob(m[1].split(".")[1]));
    return payload?.sub ? { id: payload.sub } : null;
  } catch {
    return null;
  }
}

async function getAccessToken(refresh_token: string) {
  const form = new URLSearchParams();
  form.set("client_id", CLIENT_ID);
  form.set("client_secret", CLIENT_SECRET);
  form.set("grant_type", "refresh_token");
  form.set("refresh_token", refresh_token);

  const r = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  if (!r.ok) throw new Error(await r.text());
  const j = await r.json();
  return j.access_token as string;
}

Deno.serve(async (req) => {
  try {
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: getCorsHeaders(req) });
    }

    const url = new URL(req.url);
    console.log('[CORS]', {
      method: req.method,
      origin: req.headers.get('origin'),
      allow: getCorsHeaders(req)['Access-Control-Allow-Origin'],
      path: url.pathname,
    });

  if (ALLOWED_ALBUMS.length === 0) {
    return bad(req, 500, "Server misconfigured: PHOTOS_ALLOWED_ALBUMS must contain at least one album ID");
  }

  const user = await getAuthUser(req);
  if (!user) return bad(req, 401, "Missing or invalid Authorization bearer token");

  const tokenRes = await fetch(
    `${supabaseUrl}/rest/v1/google_oauth?user_id=eq.${user.id}&select=refresh_token`,
    {
      headers: {
        Authorization: req.headers.get("authorization") || "",
        apikey: supabaseKey,
      },
    }
  );
  if (!tokenRes.ok) return bad(req, 500, "Failed to read oauth link");
  const tk = await tokenRes.json();
  const refresh_token = tk?.[0]?.refresh_token;
  if (!refresh_token) return bad(req, 400, "No linked Google Photos account");

  const access_token = await getAccessToken(refresh_token);

  const stateRes = await fetch(
    `${supabaseUrl}/rest/v1/photos_import_state?user_id=eq.${user.id}&select=*`,
    {
      headers: {
        Authorization: req.headers.get("authorization") || "",
        apikey: supabaseKey,
      },
    }
  );
  const stateJson = stateRes.ok ? await stateRes.json() : [];
  let lastSeen: string | undefined = stateJson?.[0]?.last_seen_media_time;
  let nextPageToken: string | undefined = stateJson?.[0]?.next_page_token;

  let body: any = {};
  if (req.method === 'POST') {
    body = await req.json().catch(() => ({}));
  }
  const reqPageSize = Math.max(1, Math.min(Number(body?.page_size ?? 50), 100));
  const pageSize = Math.min(reqPageSize, MAX_ITEMS_PER_RUN);
  const maxPages = Math.min(Number(body?.max_pages ?? 1), MAX_PAGES_PER_RUN);

  const albumUrl = normalizeAlbumUrl(body?.album_url);
  const albumLabel: string | undefined = body?.album_label;
  const albumIdFromClient: string | undefined = body?.album_id;

  if (ALLOWED_ALBUMS.length > 0) {
    if (!albumUrl || !ALLOWED_ALBUMS.includes(albumUrl)) {
      return json(req, {
        error: "album_not_allowed",
        message: "This album is not permitted. Please select an approved album.",
        allowed_albums: ALLOWED_ALBUMS
      }, 403);
    }
  }

  const albumId = extractAlbumId(albumUrl ?? "");
  if (!albumId && ALLOWED_ALBUMS.length > 0) {
    return bad(req, 400, "Album URL is required");
  }

  let imported = 0;
  let pages = 0;

  while (pages < maxPages && imported < MAX_ITEMS_PER_RUN) {
    pages++;

    const searchPayload: Record<string, unknown> = {
      albumId,
      pageSize,
      pageToken: nextPageToken,
    };

    const r = await fetch(PHOTOS_API, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(searchPayload),
    });

    if (!r.ok) {
      const err = await r.text();
      return bad(req, 502, `Google Photos error: ${err}`);
    }

    const j = await r.json();
    const items: any[] = j.mediaItems || [];
    nextPageToken = j.nextPageToken || undefined;

    for (const it of items) {
      if (imported >= MAX_ITEMS_PER_RUN) break;

      const mediaId = it.id as string;
      const createTime = it.mediaMetadata?.creationTime
        ? new Date(it.mediaMetadata.creationTime)
        : undefined;
      const mime = (it.mimeType || "").toLowerCase();

      if (![...ALLOWED_MIME].some(allowed => mime.startsWith(allowed))) continue;

      if (
        lastSeen &&
        createTime &&
        new Date(lastSeen).getTime() >= createTime.getTime()
      ) {
        nextPageToken = undefined;
        break;
      }

      const row = {
        user_id: user.id,
        source: "google-photos",
        provider_id: mediaId,
        path_or_url: it.productUrl || null,
        thumb_url: it.baseUrl ? `${it.baseUrl}=w256-h256` : null,
        captured_at: createTime?.toISOString() ?? null,
        lat: it.mediaMetadata?.location?.latitude ?? null,
        lng: it.mediaMetadata?.location?.longitude ?? null,
        exif_json: it.mediaMetadata ?? null,
        album_id: albumIdFromClient,
        album_label: albumLabel,
        album_url: albumUrl,
      };

      const ins = await fetch(`${supabaseUrl}/rest/v1/photos`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Prefer: "resolution=ignore-duplicates",
          Authorization: req.headers.get("authorization") || "",
          apikey: supabaseKey,
        },
        body: JSON.stringify(row),
      });

      if (!ins.ok && ins.status !== 409) {
        const err = await ins.text();
        console.warn("Insert failed", err);
        continue;
      }

      imported++;
      if (!lastSeen && createTime) lastSeen = createTime.toISOString();
      if (
        createTime &&
        (!lastSeen || new Date(createTime) > new Date(lastSeen))
      ) {
        lastSeen = createTime.toISOString();
      }
    }

    if (!nextPageToken) break;
  }

  await fetch(`${supabaseUrl}/rest/v1/photos_import_state`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      Prefer: "resolution=merge-duplicates",
      Authorization: req.headers.get("authorization") || "",
      apikey: supabaseKey,
    },
    body: JSON.stringify({
      user_id: user.id,
      provider: "google_photos",
      last_seen_media_time: lastSeen ?? null,
      next_page_token: nextPageToken ?? null,
      updated_at: new Date().toISOString(),
    }),
  });

  return json(req, {
    imported,
    pages,
    last_seen: lastSeen ?? null,
    has_more: !!nextPageToken,
    album_url: albumUrl,
    caps: {
      MAX_ITEMS_PER_RUN,
      MAX_PAGES_PER_RUN,
      page_size_used: pageSize,
    },
  }, 200);

  } catch (e: any) {
    console.error('[EDGE ERROR]', e?.stack || e);
    return bad(req, 500, 'Internal Server Error');
  }
});
