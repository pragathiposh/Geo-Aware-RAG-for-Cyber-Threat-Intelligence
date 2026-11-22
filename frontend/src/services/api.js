export function getApiBaseUrl(config = globalThis.GEORAG_CONFIG) {
  const configured = config?.apiBaseUrl;
  if (typeof configured !== "string" || !configured.trim()) {
    throw new Error("The API address is not configured. Set GEORAG_API_URL when starting the frontend server.");
  }
  try {
    const url = new URL(configured);
    if (!["http:", "https:"].includes(url.protocol)) throw new Error();
    return url.toString().replace(/\/$/, "");
  } catch {
    throw new Error("The configured API address is invalid.");
  }
}

export async function queryCTI(query, { fetchImpl = globalThis.fetch, baseUrl } = {}) {
  const cleanQuery = String(query ?? "").trim();
  if (!cleanQuery) throw new Error("Enter a CTI question before submitting.");
  if (cleanQuery.length > 4000) throw new Error("Queries must be 4,000 characters or fewer.");
  const apiUrl = baseUrl ? getApiBaseUrl({ apiBaseUrl: baseUrl }) : getApiBaseUrl();
  let response;
  try {
    response = await fetchImpl(`${apiUrl}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: cleanQuery }),
    });
  } catch {
    throw new Error("Could not reach the CTI API. Check that the backend is running and the configured API address is correct.");
  }
  let payload;
  try { payload = await response.json(); } catch { payload = {}; }
  if (!response.ok) {
    const safeMessage = payload?.detail?.error?.message ?? payload?.error?.message;
    throw new Error(typeof safeMessage === "string" ? safeMessage : `The CTI API returned an error (${response.status}).`);
  }
  return payload;
}
