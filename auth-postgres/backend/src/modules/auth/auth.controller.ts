import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import { asyncHandler } from "../../utils/asyncHandler";
import { Session, TokenBlacklist } from "./index";
import { ApiError } from "../../utils/ApiError";
import { ApiResponse } from "../../utils/ApiResponse";
import { hashToken } from "../../utils/hash.util";
import { UserService } from "../../services/user.service";
import {
  getRefreshTokenClearCookieOptions,
  getRefreshTokenCookieOptions,
} from "../../utils/refreshCookie.util";

export const registerUser = asyncHandler(
  async (req: Request, res: Response) => {
    const { email, password, confirmPassword } = req.body;

    const isExist = await UserService.findByEmail(email);
    if (isExist) {
      throw new ApiError(409, "User already registered");
    }

    if (password !== confirmPassword) {
      throw new ApiError(400, "Password and confirm Password do not match");
    }

    const newUser = await UserService.create(email, password);

    return res
      .status(201)
      .json(new ApiResponse(201, UserService.toSafeUser(newUser), "User registered successfully!"));
  }
);

export const loginUser = asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const user = await UserService.findByEmail(email);

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  const isValidUser = await user.comparePassword(password);
  if (!isValidUser) {
    throw new ApiError(400, "Wrong Password");
  }

  const accessToken = user.generateAccessToken();
  const refreshToken = user.generateRefreshToken();

  const userID = user.id
  const hashedToken = hashToken(refreshToken);
  const expiryDate = new Date()
  expiryDate.setDate(expiryDate.getDate() + 7);

  await Session.create({
    userId: userID,
    refreshToken: hashedToken,
    expiresAt: expiryDate,
  });

  const cookieOpts = getRefreshTokenCookieOptions();

  return res
    .status(200)
    .cookie("refreshToken", refreshToken, cookieOpts)
    .json(
      new ApiResponse(
        200,
        {
          user: UserService.toSafeUser(user),
          accessToken,
        },
        "User logged in successfully"
      )
    );
});

export const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  // Clear refresh token in database
  // We prefer the token on req (from refresh flow) but fallback to cookie for standard flow
  const refreshToken = (req as any).refreshToken || req.cookies?.refreshToken;

  if (refreshToken) {
    const hashed = hashToken(refreshToken);
    await Session.findOneAndDelete({ refreshToken: hashed });
  }

  // Blacklist the current access token
  const accessToken = (req as any).accessToken;
  if (accessToken) {
    const decoded = jwt.decode(accessToken) as any;
    const expiresAt = decoded?.exp
      ? new Date(decoded.exp * 1000)
      : new Date(Date.now() + 15 * 60 * 1000); // fallback to 15m from now

    await TokenBlacklist.create({
      tokenHash: hashToken(accessToken),
      expiresAt: expiresAt,
    });
  }

  return res
    .status(200)
    .clearCookie("refreshToken", getRefreshTokenClearCookieOptions())
    .json(new ApiResponse(200, {}, "User logged out successfully"));
});
