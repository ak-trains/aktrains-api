import { validationResult } from "express-validator";
import {DB} from "../config";
import { CustomErrorService,CustomHelperSerice, CustomJwtService } from "../services";
import { BANNED_USER_ACCOUNT, NEW_SYSTEM_DETECTED, TAMPERED_DATA, TAMPERED_SYSTEM, QUOTA_EXPIRED, USER_NOT_FOUND } from "../constants";
import jks from "json-keys-sort";
import CryptoJS from "crypto-js";
import moment from "moment";

const database = DB;
const usersRef = database.ref("users");
const historyRef = database.ref("history");
const addonsRef = database.ref("addons");
const patchesRef = database.ref("patches");
const libraryRef = database.ref("library");

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

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"sys-check");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(QUOTA_EXPIRED));

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

            const snapshot1 = await historyRef.child(req.user.uid).orderByChild("createdAt").limitToFirst(10).get();
            
            if(!snapshot1.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data1 = await snapshot1.val();

          

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess(BANNED_USER_ACCOUNT));

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"details");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(QUOTA_EXPIRED));

              const history = [];

              for (const d in data1){
                history.push(data1[d]);
              }

            const info = {
                uid:user.uid,
                email:user.email,
                country:user.info.country,
                name:`${user.info.fname} ${user.info.lname}`,
                secret:user.info.secret,
                ipAddress:user.auth.ipAddress,
                lastLoginAt:user.auth.lastLoginAt,
                lastLogoutAt:user.auth.lastLogoutAt,
                history:history,
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

            const addons = [];

            const patches = [];
            
            const snapshot = await addonsRef.child("xindex").get();

            const indexes = await snapshot.val();

            for (const index in indexes){

                const snapshot = await libraryRef.child(indexes[index]).child("d2cc8050-e430-433a-9d5c-7b1e0022ab7c").get();

                if (!snapshot.exists()) {
                    delete indexes[index];
                }
            }


            for (const index in indexes){

                const snapshot = await addonsRef.child(indexes[index]).get();
                const snapshot1 = await patchesRef.child(indexes[index]).get();

               if (snapshot.exists()) {
                const addon = await snapshot.val();
                addons.push(addon);
               }

               if (snapshot1.exists()) {
                const patch = await snapshot1.val();
                patches.push(patch);
               }    
            }

            const token = CustomJwtService.signSystemToken({addons,patches});

            const response = {
                status:200,
                data:{libraryToken:token},
                message:null,
            }

            return res.status(200).json(response);

        } catch (error) {
            return next(error);
        }
    },
};

export default userController;