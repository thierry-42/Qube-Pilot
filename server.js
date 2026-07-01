"use strict";

const http = require("node:http");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT || 10000);
const WEBHOOK_API_KEY = process.env.WEBHOOK_API_KEY || "";
const DEMO_MODE =
  String(process.env.DEMO_MODE || "true").toLowerCase() === "true";

const DEFAULT_TIME_ZONE = process.env.DEFAULT_TIME_ZONE || "Europe/London";
const GOOGLE_CALENDAR_ID = process.env.GOOGLE_CALENDAR_ID || "";
const GOOGLE_SERVICE_ACCOUNT_EMAIL =
  process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || "";
const GOOGLE_PRIVATE_KEY = (process.env.GOOGLE_PRIVATE_KEY || "").replace(
  /\\n/g,
  "\n"
);

function respondJson(response, statusCode, body) {
  response.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });

  response.end(JSON.stringify(body));
}

function safeEquals(actual, expected) {
  const actualBuffer = Buffer.from(actual || "");
  const expectedBuffer = Buffer.from(expected || "");

  return (
    actualBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actualBuffer, expectedBuffer)
  );
}

function isAuthorised(request) {
  const suppliedKey =
    request.headers["x-qube-webhook-key"] ||
    String(request.headers.authorization || "").replace(/^Bearer\s+/i, "");

  return (
    Boolean(WEBHOOK_API_KEY) && safeEquals(String(suppliedKey), WEBHOOK_API_KEY)
  );
}

function parseJsonBody(request) {
  return new Promise((resolve, reject) => {
    let rawBody = "";

    request.on("data", (chunk) => {
      rawBody += chunk;

      if (rawBody.length > 256 * 1024) {
        reject(new Error("Request body is too large."));
        request.destroy();
      }
    });

    request.on("end", () => {
      if (!rawBody) {
        resolve({});
        return;
      }

      try {
        resolve(JSON.parse(rawBody));
      } catch {
        reject(new Error("Request body must be valid JSON."));
      }
    });

    request.on("error", reject);
  });
}

function toIsoDateTime(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  const text = String(value).trim();

  // Supports HubSpot-style Unix milliseconds and standard ISO timestamps.
  const date = /^\d{13}$/.test(text) ? new Date(Number(text)) : new Date(text);

  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function makeGoogleEventId(dealId) {
  // Google event IDs only permit lowercase base32hex characters.
  const cleanedDealId = String(dealId)
    .toLowerCase()
    .replace(/[^a-v0-9]/g, "");

  return `qubedeal${cleanedDealId}`.slice(0, 1024);
}

function createGoogleServiceAccountJwt() {
  const now = Math.floor(Date.now() / 1000);
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");

  const header = encode({
    alg: "RS256",
    typ: "JWT",
  });

  const claims = encode({
    iss: GOOGLE_SERVICE_ACCOUNT_EMAIL,
    scope: "https://www.googleapis.com/auth/calendar",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  });

  const unsignedToken = `${header}.${claims}`;

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(unsignedToken);
  signer.end();

  const signature = signer.sign(GOOGLE_PRIVATE_KEY, "base64url");

  return `${unsignedToken}.${signature}`;
}

async function getGoogleAccessToken() {
  const assertion = createGoogleServiceAccountJwt();

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });

  const payload = await response.json();

  if (!response.ok || !payload.access_token) {
    throw new Error(
      `Google token request failed: ${
        payload.error_description || payload.error || response.status
      }`
    );
  }

  return payload.access_token;
}

async function googleCalendarRequest({ method, eventId, event, accessToken }) {
  const calendarId = encodeURIComponent(GOOGLE_CALENDAR_ID);
  const googleEventId = encodeURIComponent(eventId);

  const url = eventId
    ? `https://www.googleapis.com/calendar/v3/calendars/${calendarId}/events/${googleEventId}?sendUpdates=none`
    : `https://www.googleapis.com/calendar/v3/calendars/${calendarId}/events?sendUpdates=none`;

  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(event),
  });

  const payload = await response.json();

  if (!response.ok) {
    const error = new Error(
      payload?.error?.message ||
        `Google Calendar API failed with ${response.status}`
    );

    error.status = response.status;
    throw error;
  }

  return payload;
}

async function upsertGoogleCalendarEvent(input) {
  if (
    !GOOGLE_CALENDAR_ID ||
    !GOOGLE_SERVICE_ACCOUNT_EMAIL ||
    !GOOGLE_PRIVATE_KEY
  ) {
    throw new Error("Google Calendar configuration is incomplete.");
  }

  const eventId = makeGoogleEventId(input.dealId);

  const event = {
    id: eventId,
    summary: input.title,
    description: input.description,
    location: input.location,
    start: {
      dateTime: input.startDateTime,
      timeZone: input.timeZone,
    },
    end: {
      dateTime: input.endDateTime,
      timeZone: input.timeZone,
    },
    extendedProperties: {
      private: {
        hubspotDealId: input.dealId,
        integration: "qube-calendar-pilot",
      },
    },
  };

  const accessToken = await getGoogleAccessToken();

  try {
    const created = await googleCalendarRequest({
      method: "POST",
      eventId: null,
      event,
      accessToken,
    });

    return {
      ...created,
      syncStatus: "created",
    };
  } catch (error) {
    // If HubSpot retries the webhook, update the existing event instead.
    if (error.status !== 409) {
      throw error;
    }

    const updated = await googleCalendarRequest({
      method: "PUT",
      eventId,
      event,
      accessToken,
    });

    return {
      ...updated,
      syncStatus: "updated",
    };
  }
}

function failureResponse(message) {
  return {
    success: false,
    syncStatus: "failed",
    eventId: "",
    eventUrl: "",
    provider: DEMO_MODE ? "demo" : "google",
    errorMessage: message,
  };
}

const server = http.createServer(async (request, response) => {
  const url = new URL(
    request.url,
    `http://${request.headers.host || "localhost"}`
  );

  if (request.method === "GET" && url.pathname === "/health") {
    respondJson(response, 200, {
      ok: true,
      demoMode: DEMO_MODE,
      googleConfigured: Boolean(
        GOOGLE_CALENDAR_ID && GOOGLE_SERVICE_ACCOUNT_EMAIL && GOOGLE_PRIVATE_KEY
      ),
    });

    return;
  }

  if (request.method !== "POST" || url.pathname !== "/calendar-events") {
    respondJson(response, 404, {
      error: "Not found.",
    });

    return;
  }

  if (!isAuthorised(request)) {
    respondJson(
      response,
      401,
      failureResponse("Unauthorised webhook request.")
    );
    return;
  }

  try {
    const body = await parseJsonBody(request);

    const dealId = String(body.dealId || "").trim();
    const startDateTime = toIsoDateTime(body.startDateTime);
    const endDateTime = toIsoDateTime(body.endDateTime);
    const timeZone = String(body.timeZone || DEFAULT_TIME_ZONE).trim();

    if (!dealId || !startDateTime || !endDateTime) {
      respondJson(
        response,
        400,
        failureResponse("dealId, startDateTime, and endDateTime are required.")
      );
      return;
    }

    if (new Date(endDateTime) <= new Date(startDateTime)) {
      respondJson(
        response,
        400,
        failureResponse("endDateTime must be after startDateTime.")
      );
      return;
    }

    const calendarInput = {
      dealId,
      title: String(
        body.title || `Qube office viewing | Deal ${dealId}`
      ).trim(),
      description: String(
        body.description || `Created by HubSpot for deal ${dealId}`
      ).trim(),
      location: String(body.location || "").trim(),
      startDateTime,
      endDateTime,
      timeZone,
    };

    // First-stage pilot: validates HubSpot → Render communication only.
    if (DEMO_MODE) {
      console.log("[demo] Calendar event request received:", calendarInput);

      respondJson(response, 200, {
        success: true,
        syncStatus: "demo-created",
        eventId: `demo-${dealId}`,
        eventUrl: "",
        provider: "demo",
        errorMessage: "",
      });

      return;
    }

    const event = await upsertGoogleCalendarEvent(calendarInput);

    respondJson(response, 200, {
      success: true,
      syncStatus: event.syncStatus,
      eventId: event.id || "",
      eventUrl: event.htmlLink || "",
      provider: "google",
      errorMessage: "",
    });
  } catch (error) {
    console.error("[calendar-events] Failed:", error.message);

    respondJson(
      response,
      500,
      failureResponse(
        "Calendar event could not be created. Check the Render logs."
      )
    );
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Qube calendar pilot listening on port ${PORT}`);
});
