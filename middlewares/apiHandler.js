import {MAINTAINANCE_MODE,CLIENT_APP_KEY,CLIENT_APP_ID,CLIENT_APP_VER} from "../config";
import {CustomErrorService,CustomHelperSerice} from "../services";
import {validationResult} from "express-validator";
import CryptoJS from "crypto-js";
import { PROTECTED_RESOURCE, UNDER_MAINTAINANCE, UNSUPPORTED_CLIENT } from "../constants";

const apiHandler = async (req,res,next)=>{

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        const extractedErrors = [];
        errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
        return next(CustomErrorService.unAuthorizedAccess(PROTECTED_RESOURCE));
    }

    if(MAINTAINANCE_MODE==="true") return next(CustomErrorService.serverUnavailable(UNDER_MAINTAINANCE));
    
    const secret = req.headers.secret;
    const signature = req.headers.signature;

    const data = CustomHelperSerice.decrypt(secret);
    
    const hash = CryptoJS.SHA256(data).toString();
    

    if(hash!==signature) return next(CustomErrorService.unAuthorizedAccess(PROTECTED_RESOURCE));

    const {timeStamp,appId,appVer,apiKey} = JSON.parse(data);

    var ogDate = new Date(Date.parse(timeStamp)); 
    var ckDate   = new Date();
    var timeDiff = (ckDate.getTime() - ogDate.getTime()) / 1000;

    if(timeDiff>30) return next(CustomErrorService.unAuthorizedAccess(PROTECTED_RESOURCE));

    if(apiKey!==CLIENT_APP_KEY) return next(CustomErrorService.unAuthorizedAccess(PROTECTED_RESOURCE));

    if(appId!==CLIENT_APP_ID) return next(CustomErrorService.unAuthorizedAccess(UNSUPPORTED_CLIENT));

    if(appVer!==CLIENT_APP_VER) return next(CustomErrorService.unAuthorizedAccess(UNSUPPORTED_CLIENT));

    return next();
};

export default apiHandler;

