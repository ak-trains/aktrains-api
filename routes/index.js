import express from "express";
import {validator} from "../validators";
import { rateLimit } from "express-rate-limit";
import {authHandler} from "../middlewares"
import {authController, recoveryController,userController} from "../controllers";
import { CustomErrorService } from "../services";
import { ATTEMPTS_EXPIRED } from "../constants";

const rtLimit = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

const router = express.Router();

router.get("/library",userController.library);

const authRouter = express.Router();
const recoveryRouter = express.Router();
const userRouter = express.Router();

router.use("/api/client/auth",rtLimit,authRouter);
router.use("/api/client/recovery",rtLimit,validator.userAuth(),authHandler.recovery,recoveryRouter);
router.use("/api/client/user",rtLimit,validator.userAuth(),authHandler.legacy,userRouter);

authRouter.post("/login",validator.login(),authController.login);                   
authRouter.post("/register",validator.register(),authController.register);          
authRouter.post("/challenge",validator.challenge(),authController.challenge);
authRouter.post("/validate",validator.validate(),authController.validate);

recoveryRouter.post("/password",validator.password(),recoveryController.password);
recoveryRouter.post("/system",validator.system(),recoveryController.system);

userRouter.post("/system",validator.system(),userController.system);
userRouter.post("/details",userController.details);
userRouter.post("/library",userController.library);


export default router;