import { validationResult } from "express-validator";
import { ACCESS_DENIED, BAD_AUTHORIZATION, INSUFFICIENT_PRIVILEGES, TAMPERED_DATA } from "../constants";
import { CustomErrorService, CustomJwtService,CustomHelperSerice } from "../services";
import { DB } from "../config";

const database =DB;
const usersRef = database.ref("users");

const authHandler = {
    async recovery(req,res,next){
    
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));
        }

        const token = req.headers.authorization;

        try {
            const {uid,email,isAuth,type} = CustomJwtService.verifyOnlineToken(token);

            if(isAuth) return next(CustomErrorService.forbiddenAccess(INSUFFICIENT_PRIVILEGES));

            const snapshot = await usersRef.orderByChild("email").equalTo(email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));

            const data = await snapshot.val();

            const user = data[uid];

            if(user===undefined || user===null) return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            if(user.auth.onlineToken===undefined || user.auth.onlineToken===null) return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));

            if(user.auth.onlineToken!==token) return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));

            req.user = {uid,email,type};

            next();

        } catch (error) {
            return next(CustomErrorService.unAuthorizedAccess(BAD_AUTHORIZATION));
        }
    },
    async legacy(req,res,next){
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));
        }

        const token = req.headers.authorization;
    
        try {
            const {uid,email,isAuth} = CustomJwtService.verifyOnlineToken(token);

            if(!isAuth) return next(CustomErrorService.forbiddenAccess(INSUFFICIENT_PRIVILEGES));

            const snapshot = await usersRef.orderByChild("email").equalTo(email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));

            const data = await snapshot.val();

            const user = data[uid];

            if(user===undefined || user===null) return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            if(user.auth.onlineToken===undefined || user.auth.onlineToken===null) return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));

            if(user.auth.onlineToken!==token) return next(CustomErrorService.unAuthorizedAccess(ACCESS_DENIED));

            req.user = {uid,email};

            next();

        } catch (error) {
            return next(CustomErrorService.unAuthorizedAccess(BAD_AUTHORIZATION));
        }
    },
}

export default authHandler;