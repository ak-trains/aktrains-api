import express from "express";
import {validator} from "../validators";
import { rateLimit } from "express-rate-limit";
import {authHandler} from "../middlewares"
import {authController, recoveryController} from "../controllers";

// const atLimit = rateLimit({windowMs:150000,max:1000});//windowMs:150000,max:1
// const auLimit = rateLimit({windowMs:3600000,max:1000});//windowMs:3600000,max:3
// const vrLimit = rateLimit({windowMs:1800000,max:1000});//windowMs:1800000,max:5

const router = express.Router();

const authRouter = express.Router();
const recoveryRouter = express.Router();
const userRouter = express.Router();
const appRouter = express.Router();

router.use("/auth",authRouter);
router.use("/recovery",validator.userAuth(),authHandler.recovery,recoveryRouter);
router.use("/user",validator.userAuth(),authHandler.legacy,userRouter);
router.use("/app",validator.userAuth(),authHandler.legacy,appRouter);

authRouter.post("/login",validator.login(),authController.login);//DONE                   
authRouter.post("/register",validator.register(),authController.register);//DONE          
authRouter.post("/challenge",validator.challenge(),authController.challenge);//DONE
authRouter.post("/validate",validator.validate(),authController.validate);//DONE

recoveryRouter.post("/password",validator.password(),recoveryController.password);//DONE
recoveryRouter.post("/system",validator.system(),recoveryController.system);

userRouter.post("/library");
userRouter.post("/system");

appRouter.post("/config");

export default router;