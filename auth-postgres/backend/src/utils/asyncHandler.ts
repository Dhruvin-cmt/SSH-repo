import { NextFunction, Request, Response } from "express"

export const asyncHandler = (cbFunction : (req: Request, res: Response, next : NextFunction) => any) => {
    return (req: Request, res: Response, next : NextFunction) => {
        Promise.resolve(cbFunction(req,res,next)).catch((err) =>  next(err))
    }
}