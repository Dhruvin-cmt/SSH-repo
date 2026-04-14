import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { ApiError } from "../../utils/ApiError";
import { prisma } from "../../config/database";

type UserRow = {
  id: string;
  email: string;
  passwordHash: string;
  isActive: boolean;
  updatedBy: string | null;
  updatedAt: Date;
  createdAt: Date;
};

export interface IUser {
  id: string;
  email: string;
  password?: string;
  isActive: boolean;
  updatedBy?: string;
  updatedAt: Date;
  createdAt: Date;
  comparePassword(password: string): Promise<boolean>;
  generateAccessToken(): string;
  generateRefreshToken(): string;
}

const toIUser = (row: UserRow, includePassword = true): IUser => {
  const user: IUser = {
    id: row.id,
    email: row.email,
    password: includePassword ? row.passwordHash : undefined,
    isActive: row.isActive,
    updatedBy: row.updatedBy ?? undefined,
    updatedAt: row.updatedAt,
    createdAt: row.createdAt,
    comparePassword: async (password: string) => {
      if (!password || !includePassword || !row.passwordHash) return false;
      return bcrypt.compare(password, row.passwordHash);
    },
    generateAccessToken: () => {
      const secret = process.env.JWT_SECRET;
      if (!secret || secret.length < 32) {
        throw new ApiError(500, "JWT_SECRET must be set and at least 32 characters long");
      }
      return jwt.sign({ id: row.id }, secret, { expiresIn: "15m" });
    },
    generateRefreshToken: () => crypto.randomBytes(64).toString("hex"),
  };

  return user;
};

export const User = {
  async findOne(filter: { email?: string; id?: string }) {
    const row = await prisma.user.findFirst({
      where: {
        ...(filter.email ? { email: filter.email.toLowerCase() } : {}),
        ...(filter.id ? { id: filter.id } : {}),
      },
    });

    return row ? toIUser(row, true) : null;
  },

  async create(data: { email: string; password: string }) {
    const passwordHash = await bcrypt.hash(data.password, 10);
    const row = await prisma.user.create({
      data: {
        email: data.email.toLowerCase(),
        passwordHash,
      },
    });
    return toIUser(row, false);
  },

  async findSafeById(id: string) {
    const row = await prisma.user.findUnique({ where: { id } });
    return row ? toIUser(row, false) : null;
  },

  async findSafeOne(filter: { email?: string; id?: string }) {
    const row = await prisma.user.findFirst({
      where: {
        ...(filter.email ? { email: filter.email.toLowerCase() } : {}),
        ...(filter.id ? { id: filter.id } : {}),
      },
    });
    return row ? toIUser(row, false) : null;
  },
};
