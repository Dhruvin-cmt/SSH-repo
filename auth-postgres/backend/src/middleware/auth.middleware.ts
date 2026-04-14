import { NextFunction, Request, Response } from "express";
import { ApiError } from "../utils/ApiError";
import jwt from "jsonwebtoken";
import { User } from "../modules/user/index";
import { Session, TokenBlacklist, AuthService } from "../modules/auth";
import { asyncHandler } from "../utils/asyncHandler";
import { hashToken } from "../utils/hash.util";
import { getRefreshTokenCookieOptions } from "../utils/refreshCookie.util";

interface CustomJwtPayload extends jwt.JwtPayload {
  id: string;
}

/**
 * Helper to extract the Bearer token from the Authorization header.
 */
const getBearerToken = (req: Request): string | null => {
  const authHeader = req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;
  return authHeader.replace("Bearer ", "");
};

/**
 * Middleware to ensure the user is authenticated.
 * Handles both active access tokens and automatic token refreshing.
 */
export const isUserAuthenticated = asyncHandler(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const accessToken = getBearerToken(req);

      if (!accessToken) {
        throw new ApiError(401, "Access Token not found");
      }

      const secret = process.env.JWT_SECRET;
      if (!secret) {
        throw new ApiError(500, "Jwt Secret Key is missing in environment");
      }

      try {
        // 0. Check Blacklist
        const tokenHash = hashToken(accessToken);
        const isBlacklisted = await TokenBlacklist.findOne({ tokenHash });
        if (isBlacklisted) {
          throw new ApiError(401, "Token is blacklisted. Please log in again.");
        }

        // 1. Verify Access Token
        const decoded = jwt.verify(accessToken, secret) as CustomJwtPayload;

        if (!decoded.id) {
          throw new ApiError(401, "Invalid Access Token Payload");
        }

        // Use the new safe lookup static method
        const user = await User.findSafeById(decoded.id);

        if (!user) {
          throw new ApiError(404, "User not found");
        }

        if (!user.isActive) {
          throw new ApiError(403, "User account is deactivated (banned)");
        }

        req.user = user;
        (req as any).accessToken = accessToken;
        return next();
      } catch (error: any) {
        if (error instanceof ApiError) {
          throw error;
        }

        // 2. Handle Token Expiration via rotated refresh logic
        if (error.name === "TokenExpiredError") {
          const oldRefreshToken = req.cookies?.refreshToken;

          // Delegate to the decoupled AuthService
          const { user, newAccessToken, newRefreshToken } =
            await AuthService.refreshUserSession(oldRefreshToken);

          // 3. Set the new rotated refresh cookie
          res.cookie(
            "refreshToken",
            newRefreshToken,
            getRefreshTokenCookieOptions()
          );

          // 4. Pass new Access Token to client and request object
          res.setHeader("x-new-access-token", newAccessToken);
          req.user = user;
          (req as any).accessToken = newAccessToken;
          (req as any).refreshToken = newRefreshToken;

          return next();
        }

        throw new ApiError(401, "Invalid Access Token");
      }
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      if (process.env.NODE_ENV !== "production") {
        console.error("Auth middleware error:", error);
      }
      throw new ApiError(401, "Authentication failed");
    }
  }
);
