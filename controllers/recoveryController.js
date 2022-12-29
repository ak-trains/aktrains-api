import { validationResult } from "express-validator";
import {DB} from "../config";
import { CustomErrorService,CustomHelperSerice, CustomJwtService } from "../services";
import moment from "moment";
import jks from "json-keys-sort";
import bcrypt from "bcrypt";
import CryptoJS from "crypto-js";
import { BAD_CHALLENGE_TYPE, BANNED_USER_ACCOUNT, PASSWORD_RESET_SUCCESS, SAME_PASSWORD, SAME_SYSTEM, SYSTEM_RESET_SUCCESS, TAMPERED_DATA, TAMPERED_SYSTEM, TOO_MANY_REQUESTS, USER_NOT_FOUND } from "../constants";

const database = DB;
const usersRef = database.ref("users");
const historyRef = database.ref("history");

const recoveryController = {
    async password(req,res,next){
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {
            
            if(req.user.type!=="FGPASS") return next(CustomErrorService.conflictOccured(BAD_CHALLENGE_TYPE));

            const snapshot = await usersRef.orderByChild("email").equalTo(req.user.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data = await snapshot.val();

            const user = data[req.user.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"password");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(TOO_MANY_REQUESTS));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess(BANNED_USER_ACCOUNT));

            const match =  await bcrypt.compare(req.body.password,user.info.password);

            if(match) return next(CustomErrorService.conflictOccured(SAME_PASSWORD));

            const pass = await bcrypt.hash(req.body.password,10);

            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            user.info.password = pass;
            user.info.updatedAt = timeStamp;

            user.auth.onlineToken="N/A";
            user.auth.updatedAt = timeStamp;

            user.updatedAt = timeStamp;

            delete user.signature;

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(user.uid).update(document);

            const history = {event:"password",createdAt:timeStamp};

            await historyRef.child(user.uid).push().set(history);

            const response = {
                status:201,
                data:null,
                message:PASSWORD_RESET_SUCCESS,
            }

            return res.status(201).json(response);

        } catch (error) {
            return next(error);         
        }
    },
    async system(req,res,next){
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {

            if(req.user.type!=="RSTSYS") return next(CustomErrorService.conflictOccured(BAD_CHALLENGE_TYPE));

            const snapshot = await usersRef.orderByChild("email").equalTo(req.user.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data = await snapshot.val();

            const user = data[req.user.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"sys-reset");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(TOO_MANY_REQUESTS));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess(BANNED_USER_ACCOUNT));

            let payload;

            try {
               payload = CustomJwtService.verifySystemToken(req.body.system);
            } catch (error) {
              return next(CustomErrorService.conflictOccured(TAMPERED_SYSTEM));
            }

            if (payload.system===undefined || payload.system===null) return next(CustomErrorService.resourceNotFound(TAMPERED_SYSTEM));
                    
            const newSystem = jks.sort(payload.system,true);
            const newSign = payload.signature;

            delete newSystem.createdAt;

            const calNewSign = CryptoJS.SHA256(JSON.stringify(newSystem)).toString();

            if(calNewSign!==newSign) return next(CustomErrorService.forbiddenAccess(TAMPERED_SYSTEM));

            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            let currentSystem;
            
            if(user.system.details==="N/A"){
              
              newSystem.createdAt = timeStamp;
              newSystem.signature = calNewSign;

              currentSystem = jks.sort(newSystem,true);

            }else{
              const oldSystem = jks.sort(user.system.details,true);

              const oldSign = oldSystem.signature;
  
              delete oldSystem.createdAt;
              delete oldSystem.signature;
  
              const calOldSign = CryptoJS.SHA256(JSON.stringify(oldSystem)).toString();
  
              if(calOldSign!==oldSign) return next(CustomErrorService.forbiddenAccess(TAMPERED_SYSTEM));

              if(calNewSign===calOldSign) return next(CustomErrorService.conflictOccured(SAME_SYSTEM));

              newSystem.createdAt = timeStamp;
              newSystem.signature = calNewSign;

              currentSystem = jks.sort(newSystem,true);
            }
            
            user.system.details = currentSystem;
            user.system.updatedAt = timeStamp;

            user.updatedAt = timeStamp;

            delete user.signature;

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(user.uid).update(document);

            const history = {event:"system",createdAt:timeStamp};

            await historyRef.child(user.uid).push().set(history);

            const response = {
                status:201,
                data:null,
                message:SYSTEM_RESET_SUCCESS,
            }

            return res.status(201).json(response);

        } catch (error) {
            return next(error);
        }
    }
};

export default recoveryController;