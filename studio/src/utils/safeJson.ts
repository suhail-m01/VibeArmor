/**
 * Safe JSON response reader that never throws `Unexpected end of JSON input`
 * when a dev proxy or restarting server returns an empty or HTML body.
 */
export async function readSafeJson<T = any>(
  res: Response,
  fallbackError = "Backend API request failed."
): Promise<T> {
  const raw = await res.text();
  if (!raw || !raw.trim()) {
    throw new Error(
      res.status >= 500
        ? "VibeArmor Python Backend (127.0.0.1:8000) is starting up or not running yet — wait 2 seconds and retry."
        : fallbackError
    );
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(
      res.status >= 500
        ? "VibeArmor Python Backend (127.0.0.1:8000) returned a non-JSON error — check terminal logs."
        : fallbackError
    );
  }
}
