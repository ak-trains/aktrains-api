import express from "express";
import {validator} from "../validators";
import { rateLimit } from "express-rate-limit";
import {authHandler} from "../middlewares"
import {authController, recoveryController,userController} from "../controllers";
import { CustomErrorService } from "../services";

const rtLimit = rateLimit({windowMs:1000,max:1,handler:(req,res,next,opt)=>{
    return next(CustomErrorService.tooManyRequests());
}});//1min,max:1

const router = express.Router();

const authRouter = express.Router();
const recoveryRouter = express.Router();
const userRouter = express.Router();

router.use("/auth",rtLimit,authRouter);
router.use("/recovery",rtLimit,validator.userAuth(),authHandler.recovery,recoveryRouter);
router.use("/user",rtLimit,validator.userAuth(),authHandler.legacy,userRouter);

authRouter.post("/login",validator.login(),authController.login);//DONE                   
authRouter.post("/register",validator.register(),authController.register);//DONE          
authRouter.post("/challenge",validator.challenge(),authController.challenge);//DONE
authRouter.post("/validate",validator.validate(),authController.validate);//DONE
authRouter.post("/logout",validator.logout(),authController.logout);//DONE

recoveryRouter.post("/password",validator.password(),recoveryController.password);//DONE
recoveryRouter.post("/system",validator.system(),recoveryController.system);//DONE

userRouter.post("/system",validator.system(),userController.system);//DONE
userRouter.post("/details",userController.details);//DONE
userRouter.post("/library");


export default router;