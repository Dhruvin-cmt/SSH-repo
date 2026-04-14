import crypto from "crypto";

/**
 * Hashes a token using SHA-256 for secure storage.
 * @param token The raw token string to hash.
 * @returns The hex-encoded hash string.
 */
export const hashToken = (token: string): string => {
  if (!token) return "";
  return crypto.createHash("sha256").update(token).digest("hex");
};
