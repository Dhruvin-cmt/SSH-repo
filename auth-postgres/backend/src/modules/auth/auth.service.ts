import { Session } from "./session.schema";
import { User } from "../user/user.schema";
import { ApiError } from "../../utils/ApiError";
import { hashToken } from "../../utils/hash.util";

/**
 * Service to handle authentication-related business logic.
 */
export class AuthService {
  /**
   * Refreshes a user's session and generates new rotated tokens.
   * Handles session validation (expiry/revocation) and user checks.
   *
   * @param oldRefreshToken The raw refresh token provided by the client.
   * @returns An object containing the user and new tokens.
   */
  static async refreshUserSession(oldRefreshToken: string) {
    if (!oldRefreshToken) {
      throw new ApiError(401, "Session expired. Please log in again.");
    }

    const hashedRefreshToken = hashToken(oldRefreshToken);
    const session = await Session.findOne({
      refreshToken: hashedRefreshToken,
    });

    if (!session) {
      throw new ApiError(401, "Invalid session. Please log in again.");
    }

    // Check if session is explicitly revoked or logically expired
    if (session.isRevoked || session.expiresAt < new Date()) {
      await Session.findByIdAndDelete(session.id);
      throw new ApiError(
        401,
        "Session has expired or been revoked. Please log in again."
      );
    }

    // Find the user safely (using the new static method)
    const user = await User.findSafeById(session.userId);

    if (!user) {
      throw new ApiError(401, "Invalid User. Please log in again.");
    }

    if (!user.isActive) {
      throw new ApiError(403, "User account is deactivated (banned)");
    }

    // 3. Generate NEW tokens
    const newAccessToken = user.generateAccessToken();
    const newRefreshToken = user.generateRefreshToken();

    const newExpiry = new Date();
    newExpiry.setDate(newExpiry.getDate() + 7);

    // 4. Update Refresh Token in DB (rotation)
    session.refreshToken = hashToken(newRefreshToken);
    session.expiresAt = newExpiry;
    await session.save();

    return {
      user,
      newAccessToken,
      newRefreshToken,
    };
  }
}
