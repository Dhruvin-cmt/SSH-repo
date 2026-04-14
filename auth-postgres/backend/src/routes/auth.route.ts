import express, { Router } from "express";
import { validate } from "../middleware/validation.middleware";
import { isUserAuthenticated } from "../middleware/auth.middleware";
import { authController, authValidation } from "../modules/auth";

const router: Router = Router();

router.route('/register').post(validate(authValidation.registerSchema), authController.registerUser)
router.route('/login').post(validate(authValidation.loginSchema), authController.loginUser)
router.route('/logout').post(isUserAuthenticated,authController.logoutUser)

export default router