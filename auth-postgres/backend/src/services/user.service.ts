import { IUser, User } from "../modules/user/user.schema";

type SafeUser = Omit<IUser, "password" | "comparePassword" | "generateAccessToken" | "generateRefreshToken">;

export class UserService {
  static async findByEmail(email: string): Promise<IUser | null> {
    return User.findOne({ email });
  }

  static async create(email: string, password: string): Promise<IUser> {
    return User.create({ email, password });
  }

  static async findSafeById(id: string): Promise<IUser | null> {
    return User.findSafeById(id);
  }

  static toSafeUser(user: IUser): SafeUser {
    const { password, comparePassword, generateAccessToken, generateRefreshToken, ...safe } = user;
    return safe;
  }
}
