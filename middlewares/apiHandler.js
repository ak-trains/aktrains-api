import {MAINTAINANCE_MODE,DEBUG_MODE,CLIENT_APP_KEY,CLIENT_APP_ID,CLIENT_APP_VER} from "../config";
import {CustomErrorService,CustomHelperSerice} from "../services";
import {validationResult} from "express-validator";
import CryptoJS from "crypto-js";

const apiHandler = async (req,res,next)=>{

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        const extractedErrors = [];
        errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
        return next(CustomErrorService.unProcessableEntity(extractedErrors));
    }

    
    if(DEBUG_MODE===true) return next(CustomErrorService.serverUnavailable());

    if(MAINTAINANCE_MODE===true) return next(CustomErrorService.serverUnavailable());
    
    const secret = req.headers.secret;
    const signature = req.headers.signature;

    const data = CustomHelperSerice.decrypt(secret);

    const hash = CryptoJS.SHA256(data).toString();

    if(hash!==signature) return next(CustomErrorService.unAuthorizedAccess("Unknown Identity! Unauthorized access."));

    const {timeStamp,appId,appVer,apiKey} = JSON.parse(data);

    var ogDate = new Date(Date.parse(timeStamp)); 
    var ckDate   = new Date();
    
    var timeDiff = (ckDate.getTime() - ogDate.getTime()) / 1000;

    if(timeDiff>1800000000000) return next(CustomErrorService.unAuthorizedAccess("Request expired! Unauthorized access."));

    if(apiKey!==CLIENT_APP_KEY) return next(CustomErrorService.unAuthorizedAccess("Unknown source! Unauthorized access."));

    if(appId!==CLIENT_APP_ID) return next(CustomErrorService.serverUnavailable("Update available! Kindly update the client app."));

    if(appVer!==CLIENT_APP_VER) return next(CustomErrorService.serverUnavailable("Update available! Kindly update the client app."));

    return next();
};

export default apiHandler;

