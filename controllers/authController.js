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

const database = DB;
const usersRef = database.ref("users");
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

            const match = await bcrypt.compare(req.body.password,user.info.password);

            if(!match) return next(CustomErrorService.unAuthorizedAccess());

            if(user.info.isBanned) return next(CustomErrorService.forbiddenAccess());

            const onlinePayload = {uid:user.uid,email:user.email,isAuth:true};

            const offlinePayload = {user};

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

            const response = {
                status:200,
                data:{onlineToken,offlineToken},
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

            if (!snapshot.exists()) return next(CustomErrorService.resourceNotFound());

            const data = await snapshot.val();

            const eligible = data[req.body.secret];

            if(eligible===undefined || eligible===null) return next(CustomErrorService.resourceNotFound());
            
            const snapshot1 = await usersRef.orderByChild("email").equalTo(req.body.email).get();

            if(snapshot1.exists()) return next(CustomErrorService.conflictOccured());
            
            const uuid = uuidv4();

            const snapshot2 = await usersRef.orderByChild("uid").equalTo(uuid).get();

            if(snapshot2.exists()) return next(CustomErrorService.conflictOccured());

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
                createdAt:timeStamp,            
                updatedAt:timeStamp,
            };

            const auth = {
                appInstalled:true,
                onlineToken:"N/A",
                offlineToken:"N/A",
                challengeToken:"N/A",
                ipAddress:ip,
                lastLoginAt:"N/A",
                createdAt:timeStamp,            
                updatedAt:timeStamp,
            };

            const system = {
                current:"N/A",
                history:"N/A",
                createdAt:timeStamp,            
                updatedAt:timeStamp,
            };

            const library={
                addons:"N/A",
                createdAt:timeStamp,            
                updatedAt:timeStamp,
            }
            
            const user = {
                uid:uuid,
                email:req.body.email,
                info:info,
                auth:auth,
                system:system,
                library:library,
                createdAt:timeStamp,
                updatedAt:timeStamp,
            }

            const document = jks.sort(user,true);

            const signature = CryptoJS.SHA256(JSON.stringify(document)).toString();

            document.signature = signature;

            await usersRef.child(uuid).set(document);

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
                    message:null,
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
                    message:null,
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

            const response = {
                status:200,
                data:{onlineToken},
                message:null,
            }
            
            return res.status(200).json(response);

        } catch (error) {
            return next(error);
        }
    },
}

export default authController;