import express from "express";
import {validator} from "../validators";
import { rateLimit } from "express-rate-limit";
import {authHandler} from "../middlewares"
import {authController, recoveryController,userController} from "../controllers";
import { CustomErrorService } from "../services";
import { ATTEMPTS_EXPIRED } from "../constants";

const rtLimit = rateLimit({windowMs:3600000,max:8,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

const router = express.Router();

router.post("/api/client/",(req,res,next)=>{
    return res.status(200).json({status:200,data:null, message:"UP"});
});

const authRouter = express.Router();
const recoveryRouter = express.Router();
const userRouter = express.Router();

router.use("/api/client/auth",authRouter);
router.use("/api/client/recovery",validator.userAuth(),authHandler.recovery,recoveryRouter);
router.use("/api/client/user",validator.userAuth(),authHandler.legacy,userRouter);

authRouter.post("/login",rtLimit,validator.login(),authController.login);                   
authRouter.post("/register",rtLimit,validator.register(),authController.register);          
authRouter.post("/challenge",rtLimit,validator.challenge(),authController.challenge);
authRouter.post("/validate",rtLimit,validator.validate(),authController.validate);

recoveryRouter.post("/password",rtLimit,validator.password(),recoveryController.password);
recoveryRouter.post("/system",rtLimit,validator.system(),recoveryController.system);

userRouter.post("/system",rtLimit,validator.system(),userController.system);
userRouter.post("/details",rtLimit,userController.details);
userRouter.post("/library",rtLimit,userController.library);


export default router;