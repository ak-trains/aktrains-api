import { validationResult } from "express-validator";
import { BAD_AUTHORIZATION, INSUFFICIENT_PRIVILEGES } from "../constants";
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
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        const token = req.headers.authorization;

        try {
            const {uid,email,isAuth,type} = CustomJwtService.verifyOnlineToken(token);

            if(isAuth) return next(CustomErrorService.forbiddenAccess(INSUFFICIENT_PRIVILEGES));

            const snapshot = await usersRef.orderByChild("email").equalTo(email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const user = data[uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound());

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess());

            if(user.auth.onlineToken===undefined || user.auth.onlineToken===null) return next(CustomErrorService.unAuthorizedAccess());

            if(user.auth.onlineToken!==token) return next(CustomErrorService.unAuthorizedAccess());

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
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        const token = req.headers.authorization;
    
        try {
            const {uid,email,isAuth} = CustomJwtService.verifyOnlineToken(token);

            if(!isAuth) return next(CustomErrorService.forbiddenAccess(INSUFFICIENT_PRIVILEGES));

            const snapshot = await usersRef.orderByChild("email").equalTo(email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const user = data[uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound());

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess());

            if(user.auth.onlineToken===undefined || user.auth.onlineToken===null) return next(CustomErrorService.unAuthorizedAccess());

            if(user.auth.onlineToken!==token) return next(CustomErrorService.unAuthorizedAccess());

            req.user = {uid,email};

            next();

        } catch (error) {
            return next(CustomErrorService.unAuthorizedAccess(BAD_AUTHORIZATION));
        }
    },
}

export default authHandler;