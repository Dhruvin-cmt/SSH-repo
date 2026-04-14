import Joi from "joi";

const registerSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Provide valid E-mail",
    "string.empty": "E-mail is required",
  }),
  password: Joi.string().min(8).max(128).pattern(/^\S+$/).required().messages({
    "string.min": "Password must contain atleast 8 characters",
    "string.pattern.base": "Password must not contain spaces",
    "string.empty": "Password is required",
  }),
  confirmPassword: Joi.string().valid(Joi.ref("password")).required().messages({
    "any.only": "Password do not match",
    "string.empty": "Confirm password is required",
  }),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Provide valid E-mail",
    "string.empty": "E-mail is required",
  }),
  password: Joi.string().min(8).max(128).pattern(/^\S+$/).required().messages({
    "string.min": "Password must contain atleast 8 characters",
    "string.pattern.base": "Password must not contain spaces",
    "string.empty": "Password is required",
  }),
});

export { registerSchema, loginSchema };
