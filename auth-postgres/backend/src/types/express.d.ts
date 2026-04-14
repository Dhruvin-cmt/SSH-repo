import { IUser } from "../modules/user/user.schema";

declare global {
  namespace Express {
    interface Request {
      user?: IUser;
    }
  }
}