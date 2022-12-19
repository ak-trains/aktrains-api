import { validationResult } from "express-validator";
import {DB} from "../config";
import { CustomErrorService,CustomHelperSerice, CustomJwtService } from "../services";
import moment from "moment";
import jks from "json-keys-sort";
import bcrypt from "bcrypt";
import CryptoJS from "crypto-js";

const database = DB;
const usersRef = database.ref("users");

const recoveryController = {
    async password(req,res,next){
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {
            
            if(req.user.type!=="FGPASS") return next(CustomErrorService.conflictOccured());

            const snapshot = await usersRef.orderByChild("email").equalTo(req.user.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const user = data[req.user.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound());

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess());

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess());

            const match =  await bcrypt.compare(req.body.password,user.info.password);

            if(match) return next(CustomErrorService.conflictOccured());

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

            const response = {
                status:201,
                data:null,
                message:null,
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

            if(req.user.type!=="RSTSYS") return next(CustomErrorService.conflictOccured());

            const snapshot = await usersRef.orderByChild("email").equalTo(req.user.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const user = data[req.user.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound());

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess("FB1"));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess("FB2"));

            let payload;

            try {
               payload = CustomJwtService.verifySystemToken(req.body.system);
            } catch (error) {
              return next(CustomErrorService.conflictOccured());
            }

            if (payload.system===undefined || payload.system===null) return next(CustomErrorService.resourceNotFound());
                    
            const newSystem = jks.sort(payload.system,true);
            const newSign = payload.signature;

            delete newSystem.createdAt;
            delete newSystem.deletedAt;

            const calNewSign = CryptoJS.SHA256(JSON.stringify(newSystem)).toString();

            if(calNewSign!==newSign) return next(CustomErrorService.forbiddenAccess("FB3"));

            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            let currentSystem;
            
            if(user.system.current==="N/A" && user.system.history==="N/A"){
              
              newSystem.createdAt = timeStamp;
              newSystem.deletedAt = "N/A";
              newSystem.signature = calNewSign;

              currentSystem = jks.sort(newSystem,true);

            }else{
              const oldSystem = jks.sort(user.system.current,true);

              const oldSign = oldSystem.signature;
  
              delete oldSystem.createdAt;
              delete oldSystem.deletedAt;
              delete oldSystem.signature;
  
              const calOldSign = CryptoJS.SHA256(JSON.stringify(oldSystem)).toString();

              console.log(calOldSign);
              console.log(oldSign);
  
              if(calOldSign!==oldSign) return next(CustomErrorService.forbiddenAccess("FB4"));

              if(calNewSign===calOldSign) return next(CustomErrorService.conflictOccured());

              newSystem.createdAt = timeStamp;
              newSystem.deletedAt = "N/A";
              newSystem.signature = calNewSign;

              currentSystem = jks.sort(newSystem,true);
            }

            user.system.history = user.system.current;  
            user.system.current = currentSystem;
            user.system.updatedAt = timeStamp;

            user.updatedAt = timeStamp;

            delete user.signature;

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(user.uid).update(document);

            const response = {
                status:201,
                data:null,
                message:null,
            }

            return res.status(201).json(response);



        } catch (error) {
            
        }
    }
};

export default recoveryController;