import express from "express";
import {validator} from "../validators";
import { rateLimit } from "express-rate-limit";
import {authHandler} from "../middlewares"
import {authController, recoveryController,userController} from "../controllers";
import { CustomErrorService } from "../services";
import { ATTEMPTS_EXPIRED } from "../constants";



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

const lgRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

const rgRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

const chRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

const vlRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

authRouter.post("/login",lgRtLm,validator.login(),authController.login);                   
authRouter.post("/register",rgRtLm,validator.register(),authController.register);          
authRouter.post("/challenge",chRtLm,validator.challenge(),authController.challenge);
authRouter.post("/validate",vlRtLm,validator.validate(),authController.validate);

const srRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

const prRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});
recoveryRouter.post("/password",srRtLm,validator.password(),recoveryController.password);
recoveryRouter.post("/system",prRtLm,validator.system(),recoveryController.system);

const syRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

const dtRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

const lbRtLm = rateLimit({windowMs:3600000,max:6,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests(ATTEMPTS_EXPIRED));
}});

userRouter.post("/system",syRtLm,validator.system(),userController.system);
userRouter.post("/details",dtRtLm,userController.details);
userRouter.post("/library",lbRtLm,userController.library);


export default router;