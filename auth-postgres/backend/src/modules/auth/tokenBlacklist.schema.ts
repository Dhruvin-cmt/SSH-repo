import { prisma } from "../../config/database";

export interface ITokenBlacklist {
  id: string;
  tokenHash: string;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export const TokenBlacklist = {
  async findOne(where: { tokenHash?: string }) {
    return prisma.tokenBlacklist.findFirst({ where });
  },

  async create(data: { tokenHash: string; expiresAt: Date }) {
    return prisma.tokenBlacklist.create({ data });
  },
};
