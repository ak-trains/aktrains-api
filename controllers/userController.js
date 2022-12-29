import { validationResult } from "express-validator";
import {DB} from "../config";
import { CustomErrorService,CustomHelperSerice, CustomJwtService } from "../services";
import { BANNED_USER_ACCOUNT, NEW_SYSTEM_DETECTED, TAMPERED_DATA, TAMPERED_SYSTEM, TOO_MANY_REQUESTS, USER_NOT_FOUND } from "../constants";
import jks from "json-keys-sort";
import CryptoJS from "crypto-js";
import moment from "moment";

const database = DB;
const usersRef = database.ref("users");
const historyRef = database.ref("history");
const addonsRef = database.ref("addons");
const patchesRef = database.ref("patches");

const userController = {
    async system(req,res,next){
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {
            const snapshot = await usersRef.orderByChild("email").equalTo(req.user.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data = await snapshot.val();

            const user = data[req.user.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"sys-check");
            
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
                    
            const detectedSystem = jks.sort(payload.system,true);
            const detectedSign = payload.signature;
            delete detectedSystem.createdAt;
          
            const calDetectedSign = CryptoJS.SHA256(JSON.stringify(detectedSystem)).toString();

            if(calDetectedSign!==detectedSign) return next(CustomErrorService.forbiddenAccess(TAMPERED_SYSTEM));

            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            var isNewSystem = false;

            if(user.system.details==="N/A"){
                isNewSystem=true;
            }else{
                const existingSystem = jks.sort(user.system.details,true);
                const existingSign = existingSystem.signature;
      
                delete existingSystem.createdAt;
                delete existingSystem.signature;
    
                const calExistingSign = CryptoJS.SHA256(JSON.stringify(existingSystem)).toString();
    
                if(calExistingSign!==existingSign) return next(CustomErrorService.forbiddenAccess(TAMPERED_SYSTEM));
    
                if (calDetectedSign!==existingSign) {
                    isNewSystem=true;
                }
            }

            if (isNewSystem) {

                user.auth.onlineToken = "N/A";
                user.auth.updatedAt = timeStamp;
    
                user.updatedAt = timeStamp;
    
                delete user.signature;
    
                const document = jks.sort(user,true);
    
                const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();
    
                document.signature = signature;
    
                await usersRef.child(user.uid).update(document);
    
                const history = {event:"system-check",createdAt:timeStamp};

                await historyRef.child(user.uid).push().set(history);

                
                const response = {
                    status:200,
                    data:null,
                    message:NEW_SYSTEM_DETECTED,
                }

                return res.status(200).json(response);
            }

            const token = CustomJwtService.signSystemToken({system:user.system.details});

            const response = {
                status:200,
                data:{systemToken:token},
                message:null,
            }

            return res.status(200).json(response);

        } catch (error) {
            return next(error);
        }
    },
    async details(req,res,next){
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {
            const snapshot = await usersRef.orderByChild("email").equalTo(req.user.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data = await snapshot.val();

            const user = data[req.user.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const snapshot1 = await historyRef.child(req.user.uid).orderByChild("createdAt").equalTo(req.user.email).get();
            
            if(!snapshot1.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data1 = await snapshot1.val();

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"details");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(TOO_MANY_REQUESTS));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess(BANNED_USER_ACCOUNT));

            const info = {
                uid:user.uid,
                email:user.email,
                country:user.info.country,
                name:`${user.info.fname} ${user.info.lname}`,
                secret:user.info.secret,
                ipAddress:user.auth.ipAddress,
                lastLoginAt:user.auth.lastLoginAt,
                lastLogoutAt:user.auth.lastLogoutAt,
                history:data1,
            };

            const token = CustomJwtService.signSystemToken({info:info});


            const response = {
                status:200,
                data:{infoToken:token},
                message:null,
            }

            return res.status(200).json(response);

        } catch (error) {
            return next(error);
        }
    },
    async library(req,res,next){
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {
            const snapshot = await usersRef.orderByChild("email").equalTo(req.user.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data = await snapshot.val();

            const user = data[req.user.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"library");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(TOO_MANY_REQUESTS));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess(BANNED_USER_ACCOUNT));

            const snapshot1 = await addonsRef.get();

            const addons = snapshot1.data();


            const library = [];

        
            const info = {
                uid:user.uid,
                email:user.email,
                country:user.info.country,
                name:`${user.info.fname} ${user.info.lname}`,
                secret:user.info.secret,
                ipAddress:user.auth.ipAddress,
                lastLoginAt:user.auth.lastLoginAt,
                lastLogoutAt:user.auth.lastLogoutAt,
                history:data1,
            };

            const token = CustomJwtService.signSystemToken({info:info});


            const response = {
                status:200,
                data:{infoToken:token},
                message:null,
            }

            return res.status(200).json(response);

        } catch (error) {
            return next(error);
        }
    },
};

export default userController;