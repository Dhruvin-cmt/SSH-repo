import type { CookieOptions } from "express";

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

function refreshCookieBase(): CookieOptions {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  };
}

export function getRefreshTokenCookieOptions(): CookieOptions {
  return { ...refreshCookieBase(), maxAge: SEVEN_DAYS_MS };
}

/** Options must match `getRefreshTokenCookieOptions` path/httpOnly/secure/sameSite for the browser to clear the cookie. */
export function getRefreshTokenClearCookieOptions(): CookieOptions {
  return refreshCookieBase();
}
