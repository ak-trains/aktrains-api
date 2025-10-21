import {APP_PORT} from "./config/index.js";
import {errorHandler,apiHandler} from "./middlewares/index.js";
import express from "express";
import routes from "./routes/index.js";
import { validator } from "./validators/index.js";
import {CustomErrorService } from "./services/index.js";
import { rateLimit } from "express-rate-limit";
import { TOO_MANY_REQUESTS } from "./constants/index.js";

const app = express();

app.use(express.urlencoded({extended:false}));

app.use(express.json());

const rtLimit = rateLimit({windowMs:1000,max:1,handler:(req,res,next,opt)=>{
  return next(CustomErrorService.tooManyRequests(TOO_MANY_REQUESTS));
}});

app.use("/",rtLimit,validator.apiAuth(),apiHandler,routes);

app.use(errorHandler);

app.listen(APP_PORT,()=>console.log(`Listening on port ${APP_PORT}`));
