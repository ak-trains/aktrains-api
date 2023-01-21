import moment from "moment/moment";
import {v4 as uuidv4} from "uuid";
import requestIp from "request-ip";
import bcrypt from "bcrypt";
import crypto from "crypto";
import CryptoJS from "crypto-js";
import nodemailer from "nodemailer";
import {MAIL_USERNAME,MAIL_PASSWORD,DB} from "../config";
import {CustomErrorService,CustomJwtService,CustomHelperSerice} from "../services";
import jks from "json-keys-sort";
import otpGenerator from "otp-generator";
import { validationResult } from "express-validator";
import { ALREADY_CHALLENGED, ALREADY_LOGGED_IN, BAD_CHALLENGE_TYPE, BAD_CREDENTIALS, BANNED_USER_ACCOUNT, CHALLENGE_EXPIRED, CHALLENGE_SENT, EMAIL_ALREADY_EXISTS, IN_ELIGIBLE_TO_SIGNUP, LOGIN_SUCCESS, LOGOUT_SUCCESS, REGISTER_SUCCESS, TAMPERED_DATA, QUOTA_EXPIRED, UID_ALREADY_EXISTS, USER_NOT_FOUND, VERIFICATION_SUCCESS } from "../constants";

const database = DB;
const usersRef = database.ref("users");
const historyRef = database.ref("history");
const eligiblesRef = database.ref("eligibles");

const authController = {

    async login (req,res,next){
        
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {

            const snapshot = await usersRef.orderByChild("email").equalTo(req.body.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data = await snapshot.val();

            const user = data[req.body.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            const match = await bcrypt.compare(req.body.password,user.info.password);

            if(!match) return next(CustomErrorService.unAuthorizedAccess(BAD_CREDENTIALS));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess(BANNED_USER_ACCOUNT));

            if (user.auth.onlineToken!=="N/A") {
                try {
                   const payload =  CustomJwtService.verifyOnlineToken(user.auth.onlineToken);
                   if (payload.isAuth) return next(CustomErrorService.conflictOccured(ALREADY_LOGGED_IN));
                   
                 } catch (error) {
                    if (error.name!=="TokenExpiredError") return next(CustomErrorService.conflictOccured(ALREADY_LOGGED_IN));
                 }
            }

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"login");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(QUOTA_EXPIRED));
            
            const onlinePayload = {
                uid:user.uid,
                email:user.email,
                isAuth:true
            };

            const offlinePayload = {
                uid:user.uid,
                email:user.email,
                name:`${user.info.fname} ${user.info.lname}`,
                isBanned:user.info.isBanned,
                password:user.info.password,
                secret:user.info.secret,
                lastLoginAt:user.auth.lastLoginAt,
                signature: user.system.details.signature,
            };

            const onlineToken = CustomJwtService.signOnlineToken(onlinePayload);
            const offlineToken = CustomJwtService.signOfflineToken(offlinePayload);

            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            user.auth.ipAddress = requestIp.getClientIp(req);
            user.auth.lastLoginAt = timeStamp;
            user.auth.onlineToken = onlineToken;
            user.auth.updatedAt = timeStamp;
            user.updatedAt = timeStamp;

            delete user.signature;

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(user.uid).update(document);

            const history = {event:"login",createdAt:timeStamp};

            await historyRef.child(user.uid).push().set(history);

            const response = {
                status:200,
                data:{onlineToken,offlineToken},
                message:LOGIN_SUCCESS,
            }
            
            return res.status(200).json(response);

        } catch (error) {
            return next(error);
        }
    },  
    async register(req,res,next){

        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {
           
            const snapshot = await eligiblesRef.orderByChild("email").equalTo(req.body.email).get();

            if (!snapshot.exists()) return next(CustomErrorService.resourceNotFound(IN_ELIGIBLE_TO_SIGNUP));

            const data = await snapshot.val();

            const eligible = data[req.body.secret];

            if(eligible===undefined || eligible===null) return next(CustomErrorService.resourceNotFound(IN_ELIGIBLE_TO_SIGNUP));
            
            const snapshot1 = await usersRef.orderByChild("email").equalTo(req.body.email).get();

            if(snapshot1.exists()) return next(CustomErrorService.conflictOccured(EMAIL_ALREADY_EXISTS));
            
            const uuid = uuidv4();

            const snapshot2 = await usersRef.orderByChild("uid").equalTo(uuid).get();

            if(snapshot2.exists()) return next(CustomErrorService.conflictOccured(UID_ALREADY_EXISTS));

            const ip = requestIp.getClientIp(req);

            const pass = await bcrypt.hash(req.body.password,10);

            const rbytes = crypto.randomBytes(32).toString("hex");

            const secKey =  CryptoJS.SHA256(rbytes).toString();

            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            const info = {
                fname:req.body.fname,
                lname:req.body.lname,
                country:req.body.country,
                secret:secKey,
                password:pass,
                isBanned:false,       
                updatedAt:timeStamp,
            };

            const auth = {
                onlineToken:"N/A",
                challengeToken:"N/A",
                ipAddress:ip,
                lastLoginAt:"N/A",
                updatedAt:timeStamp,
            };

            const system = {
                details:"N/A",          
                updatedAt:timeStamp,
            };

            const count={
                login:0,
                challenge:0,
                validate:0,
                password:0,
                sysReset:0,
                sysCheck:0,
                library:0,
                details:0,
                countOf:timeStamp.substring(0,8),
                updatedAt:timeStamp,
            }
            
            const user = {
                uid:uuid,
                email:req.body.email,
                info:info,
                auth:auth,
                system:system,
                count:count,
                createdAt:timeStamp,
                updatedAt:timeStamp,
            }

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(uuid).set(document);

            const history = {event:"register",createdAt:timeStamp};

            await historyRef.child(user.uid).push().set(history);

            const transporter = nodemailer.createTransport({
                host:"us2.smtp.mailhostbox.com",
                port: 587,
                secure:false,
                auth: {user: MAIL_USERNAME,pass: MAIL_PASSWORD},
            });

            const mailOptions = {
                from: `"AKTrains" <${MAIL_USERNAME}>`,
                to: req.body.email,
                subject: "Your AKTrains Account Credentials",
                text: CustomHelperSerice.generateMessage(uuid,req.body.email),
            };


            transporter.sendMail(mailOptions, async (error)=>{
                if (error) {
                    await usersRef.child(uuid).remove();
                    return next(error);
                } 
                
               await eligiblesRef.child(req.body.secret).remove();

                const response = {
                    status:201,
                    data:null,
                    message:REGISTER_SUCCESS,
                }

                return res.status(201).json(response);
            });
                    
        } catch (error) {
            return next(error);
        }

    },
    async challenge(req,res,next){
        
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {

            if(req.body.type!=="FGPASS" && req.body.type!=="RSTSYS") return next(CustomErrorService.conflictOccured(BAD_CHALLENGE_TYPE));

            const snapshot = await usersRef.orderByChild("email").equalTo(req.body.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data = await snapshot.val();

            const user = data[req.body.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess(BANNED_USER_ACCOUNT));

            if (user.auth.onlineToken!=="N/A") {
                try {
                    CustomJwtService.verifyOnlineToken(user.auth.onlineToken);
                    return next(CustomErrorService.conflictOccured(ALREADY_LOGGED_IN));
                 } catch (error) {
                    if (error.name!=="TokenExpiredError") return next(CustomErrorService.conflictOccured(ALREADY_LOGGED_IN));
                 }
            }

            if (user.auth.challengeToken!=="N/A") {
                try {
                    CustomJwtService.verifyChallengeToken(user.auth.challengeToken);
                    return next(CustomErrorService.conflictOccured(ALREADY_CHALLENGED));
                 } catch (error) {
                    if (error.name!=="TokenExpiredError") return next(CustomErrorService.conflictOccured(ALREADY_CHALLENGED));
                 }
            }

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"challenge");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(QUOTA_EXPIRED));

            const code = otpGenerator.generate(8,{upperCaseAlphabets:true,lowerCaseAlphabets:false,specialChars:false,digits:true});
            
            const payload = {challenge:code,reason:req.body.type,uid:user.uid,email:user.email};
            
            const challengeToken = CustomJwtService.signChallengeToken(payload); 
            
            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            user.auth.challengeToken = challengeToken;
            user.auth.updatedAt = timeStamp;
            user.updatedAt = timeStamp;

            delete user.signature;

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(user.uid).update(document);

            const history = {event:"challenge",createdAt:timeStamp};

            await historyRef.child(user.uid).push().set(history);

            const transporter = nodemailer.createTransport({
                host:"us2.smtp.mailhostbox.com",
                port: 587,
                secure:false,
                auth: {user: MAIL_USERNAME,pass: MAIL_PASSWORD},
            });

            const mailOptions = {
                from: `"AKTrains" <${MAIL_USERNAME}>`,
                to: req.body.email,
                subject: "Your AKTrains Verification Code",
                text: CustomHelperSerice.generateMessage2(payload),
            };

            transporter.sendMail(mailOptions, async (error)=>{
                if (error) {
                    user.auth.challengeToken="N/A";
                    
                    delete user.signature;

                    const document = jks.sort(user,true);

                    const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

                    document.signature = signature;

                    await usersRef.child(user.uid).update(document);

                    return next(error);
                } 
                
                const response = {
                    status:201,
                    data:null,
                    message:CHALLENGE_SENT,
                }

                return res.status(201).json(response);
            });

        } catch (error) {
            return next(error);
        }
    },
    async validate(req,res,next){
        const errors = validationResult(req);
                
        if (!errors.isEmpty()) {
            const extractedErrors = [];
            errors.array().map(err=>extractedErrors.push({[err.param]:err.msg}));
            return next(CustomErrorService.unProcessableEntity(extractedErrors));
        }

        try {

            if(req.body.type!=="FGPASS" && req.body.type!=="RSTSYS") return next(CustomErrorService.conflictOccured(BAD_CHALLENGE_TYPE));

            const snapshot = await usersRef.orderByChild("email").equalTo(req.body.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const data = await snapshot.val();

            const user = data[req.body.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound(USER_NOT_FOUND));

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess(TAMPERED_DATA));

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess(BANNED_USER_ACCOUNT));

            if (user.auth.onlineToken!=="N/A") {
                try {
                    CustomJwtService.verifyOnlineToken(user.auth.onlineToken);
                    return next(CustomErrorService.conflictOccured(ALREADY_LOGGED_IN));
                 } catch (error) {
                    if (error.name!=="TokenExpiredError") return next(CustomErrorService.conflictOccured(ALREADY_LOGGED_IN));
                 }
            }
            
            let payload;

            if(user.auth.challengeToken===null || user.auth.challengeToken===undefined){
                return next(CustomErrorService.resourceNotFound(BAD_CHALLENGE_TYPE));
            }
            
            try {
                payload = CustomJwtService.verifyChallengeToken(user.auth.challengeToken);
            } catch (error) {
                if (error.name!=="TokenExpiredError"){
                    return next(CustomErrorService.forbiddenAccess(CHALLENGE_EXPIRED));
                }else{
                    return next(CustomErrorService.conflictOccured(BAD_CHALLENGE_TYPE));
                }
            }
            
            if(payload.uid!==req.body.uid) return next(CustomErrorService.unAuthorizedAccess(BAD_CREDENTIALS));
            if(payload.email!==req.body.email) return next(CustomErrorService.unAuthorizedAccess(BAD_CREDENTIALS));
            if(payload.reason!==req.body.type) return next(CustomErrorService.unAuthorizedAccess(BAD_CREDENTIALS));
            if(req.body.code!==payload.challenge) return next(CustomErrorService.unAuthorizedAccess(BAD_CREDENTIALS));


            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"validate");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests(QUOTA_EXPIRED));

            const onlinePayload = {uid:user.uid,email:user.email,isAuth:false,type:payload.reason};

            const onlineToken = CustomJwtService.signOnlineToken(onlinePayload);
            
            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            user.auth.challengeToken="N/A";
            user.auth.onlineToken = onlineToken;
            user.auth.updatedAt = timeStamp;
            user.updatedAt = timeStamp;

            delete user.signature;

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(user.uid).update(document);

            const history = {event:"validate",createdAt:timeStamp};

            await historyRef.child(user.uid).push().set(history);

            const response = {
                status:200,
                data:{onlineToken},
                message:VERIFICATION_SUCCESS,
            }
            
            return res.status(200).json(response);

        } catch (error) {
            return next(error);
        }
    }
}

export default authController;