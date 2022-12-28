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
import { BAD_CREDENTIALS, CHALLENGE_SENT, EMAIL_ALREADY_EXISTS, IN_ELIGIBLE_TO_SIGNUP, REGISTER_SUCCESS, UID_ALREADY_EXISTS, VERIFICATION_SUCCESS } from "../constants";

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
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const user = data[req.body.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound());

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess());
            
            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"login");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests());

            const match = await bcrypt.compare(req.body.password,user.info.password);

            if(!match) return next(CustomErrorService.unAuthorizedAccess());

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess());

            const onlinePayload = {
                uid:user.uid,
                email:user.email,
                isAuth:true
            };

            const offlinePayload = {
                uid:user.uid,
                email:user.email,
                info:user.info,
                library:user.library
            };

            const onlineToken = CustomJwtService.signOnlineToken(onlinePayload);
            const offlineToken = CustomJwtService.signOfflineToken(offlinePayload);

            const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");

            user.auth.appInstalled=true;
            user.auth.ipAddress = requestIp.getClientIp(req);
            user.auth.lastLoginAt = timeStamp;
            user.auth.offlineToken = offlineToken;
            user.auth.onlineToken = onlineToken;
            user.auth.updatedAt = timeStamp;
            user.updatedAt = timeStamp;

            delete user.signature;

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(user.uid).update(document);

            const history = {snapshot:user.auth,event:"login"};

            await historyRef.child(user.uid).push().set(history);

            const response = {
                status:200,
                data:{
                    uid: user.uid, 
                    email: user.email, 
                    fname: user.info.fname, 
                    lname: user.info.lname, 
                    country: user.info.country, 
                    secret: user.info.secret, 
                    ipAddress: user.auth.ipAddress, 
                    lastLoginAt: user.auth.lastLoginAt, 
                    createdAt: user.createdAt, 
                    updatedAt: user.updatedAt, 
                    onlineToken: onlineToken, 
                    offlineToken: offlineToken,
                },
                message:null,
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
                offlineToken:"N/A",
                challengeToken:"N/A",
                ipAddress:ip,
                lastLoginAt:"N/A",          
                updatedAt:timeStamp,
            };

            const system = {
                details:"N/A",          
                updatedAt:timeStamp,
            };

            const library={
                addons:"N/A",          
                updatedAt:timeStamp,
            }

            const count={
                login:0,
                logout:0,
                challenge:0,
                validate:0,
                password:0,
                sysReset:0,
                sysCheck:0,
                library:0,
                countOf:timeStamp.substring(0,8),
                updatedAt:timeStamp,
            }
            
            const user = {
                uid:uuid,
                email:req.body.email,
                info:info,
                auth:auth,
                system:system,
                library:library,
                count:count,
                createdAt:timeStamp,
                updatedAt:timeStamp,
            }

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(uuid).set(document);

            const history = {snapshot:document.auth,event:"register"};

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

            
            console.log(uuid,req.body.email);
            await eligiblesRef.child(req.body.secret).remove();

            const response = {
                status:201,
                data:null,
                message:REGISTER_SUCCESS,
            }

            return res.status(201).json(response);

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

            if(req.body.type!=="FGPASS" && req.body.type!=="RSTSYS") return next(CustomErrorService.conflictOccured());

            const snapshot = await usersRef.orderByChild("email").equalTo(req.body.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const user = data[req.body.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound());

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess());

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"challenge");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests());

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess());
            
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

            const history = {snapshot:user.auth,event:"challenge"};

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

            console.log(payload);

            const response = {
                status:201,
                data:null,
                message:CHALLENGE_SENT,
            }

            return res.status(201).json(response);

            transporter.sendMail(mailOptions, async (error)=>{
                if (error) {
                    console.log(error);
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

            if(req.body.type!=="FGPASS" && req.body.type!=="RSTSYS") return next(CustomErrorService.conflictOccured());

            const snapshot = await usersRef.orderByChild("email").equalTo(req.body.email).get();
            
            if(!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const user = data[req.body.uid];

            if(user===undefined || user===null) return next(CustomErrorService.resourceNotFound());

            const isTampered = CustomHelperSerice.checkSignature(user);
           
            if(isTampered) return next(CustomErrorService.forbiddenAccess());

            const {isAllowed,newCount} = CustomHelperSerice.checkRateLimit(user.count,"validate");
            
            user.count = newCount;

            if(!isAllowed) return next(CustomErrorService.tooManyRequests());

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess());
            
            let payload;

            if(user.auth.challengeToken===null || user.auth.challengeToken===undefined){
                return next(CustomErrorService.resourceNotFound());
            }
            
            try {
                payload = CustomJwtService.verifyChallengeToken(user.auth.challengeToken);
            } catch (error) {
                return next(CustomErrorService.conflictOccured());
            }
            
            if(payload.uid!==req.body.uid) return next(CustomErrorService.unAuthorizedAccess());
            if(payload.email!==req.body.email) return next(CustomErrorService.unAuthorizedAccess());
            if(payload.reason!==req.body.type) return next(CustomErrorService.unAuthorizedAccess());
            if(req.body.code!==payload.challenge) return next(CustomErrorService.unAuthorizedAccess());

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

            const history = {snapshot:user.auth,event:"validate"};

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
    },
}

export default authController;