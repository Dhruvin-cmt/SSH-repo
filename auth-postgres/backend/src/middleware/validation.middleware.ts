import { NextFunction, Request, Response } from "express";
import Joi from "joi";
import { ApiError } from "../utils/ApiError";

const validate = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      allowUnknown: true,
      stripUnknown: true,
    });

    if (error) {
      const errorMessage = error.details
        .map((details) => details.message)
        .join(", ");
      console.log("Validation Error:", errorMessage);
      return next(new ApiError(400, errorMessage));
    }

    req.body = value;
    next();
  };
};

export {validate}
