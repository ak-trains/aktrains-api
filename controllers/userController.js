import { validationResult } from "express-validator";
import {DB} from "../config";
import { CustomErrorService,CustomHelperSerice, CustomJwtService } from "../services";
import moment from "moment";
import jks from "json-keys-sort";
import CryptoJS from "crypto-js";

const database = DB;
const usersRef = database.ref("users");

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
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const user = data[req.user.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound());

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess("FB1"));

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"sys-check");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests());

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess("FB2"));

            let payload;

            try {
               payload = CustomJwtService.verifySystemToken(req.body.system);
            } catch (error) {
              return next(CustomErrorService.conflictOccured());
            }

            if (payload.system===undefined || payload.system===null) return next(CustomErrorService.resourceNotFound());
                    
            const detectedSystem = jks.sort(payload.system,true);
            const detectedSign = payload.signature;
            delete detectedSystem.createdAt;
          

            const calDetectedSign = CryptoJS.SHA256(JSON.stringify(detectedSystem)).toString();

            if(calDetectedSign!==detectedSign) return next(CustomErrorService.forbiddenAccess("FB3"));

            if(user.system.details==="N/A"){

                const response = {
                    status:200,
                    data:{systemToken:null},
                    message:"FB4",
                }
    
                return res.status(201).json(response);
            }

            const existingSystem = jks.sort(user.system.details,true);
            const existingSign = existingSystem.signature;
  
            delete existingSystem.createdAt;
            delete existingSystem.signature;

            const calExistingSign = CryptoJS.SHA256(JSON.stringify(existingSystem)).toString();

            if(calExistingSign!==existingSign) return next(CustomErrorService.forbiddenAccess("FB5"));

            const token = CustomJwtService.signSystemToken({system:user.system.details});

            const response = {
                status:200,
                data:{systemToken:token},
                message:null,
            }

            return res.status(201).json(response);

        } catch (error) {
            return next(error);
        }
    }
};

export default userController;