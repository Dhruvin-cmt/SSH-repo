import { prisma } from "../../config/database";

export interface IAuth {
  id: string;
  userId: string;
  refreshToken: string;
  expiresAt: Date;
  isRevoked: boolean;
  createdAt: Date;
  updatedAt: Date;
}

type SessionDoc = IAuth & {
  save: () => Promise<IAuth>;
};

const toSessionDoc = (row: IAuth): SessionDoc => {
  const doc = {
    ...row,
    save: async () => {
      const updated = await prisma.session.update({
        where: { id: doc.id },
        data: {
          refreshToken: doc.refreshToken,
          expiresAt: doc.expiresAt,
          isRevoked: doc.isRevoked,
        },
      });
      Object.assign(doc, updated);
      return { ...updated };
    },
  };

  return doc;
};

export const Session = {
  async findOne(where: { refreshToken?: string }) {
    const row = await prisma.session.findFirst({ where });
    return row ? toSessionDoc(row) : null;
  },

  async findByIdAndDelete(id: string) {
    try {
      return await prisma.session.delete({ where: { id } });
    } catch {
      return null;
    }
  },

  async findOneAndDelete(where: { refreshToken?: string }) {
    const row = await prisma.session.findFirst({ where });
    if (!row) return null;
    return prisma.session.delete({ where: { id: row.id } });
  },

  async create(data: { userId: string; refreshToken: string; expiresAt: Date; isRevoked?: boolean }) {
    return prisma.session.create({
      data: {
        userId: data.userId,
        refreshToken: data.refreshToken,
        expiresAt: data.expiresAt,
        isRevoked: data.isRevoked ?? false,
      },
    });
  },
};
