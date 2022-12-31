import CryptoJS from "crypto-js";
import {CRYPT_KEY} from "../config";
import jks from "json-keys-sort";
import moment from "moment";

class CustomHelperSerice{

    static decrypt(cipherText){
        const bytes  = CryptoJS.AES.decrypt(cipherText, CRYPT_KEY);
        const originalText = bytes.toString(CryptoJS.enc.Utf8);
        return originalText;
    }

    static encrypt(data){
        const originalText = JSON.stringify(data);
        const cipherText = CryptoJS.AES.encrypt(originalText, CRYPT_KEY).toString();
        return cipherText;
    }

    static genApiAuthHead(){
        const data = {
            "timeStamp":"2022-11-28T15:04:00",
            "appId":"313052db-33f2-4797-b983-01a056b097cd",
            "appVer":"6.0",
            "apiKey":"e0fb071814d805277350f4f2c421dc1d95fa6cf036fdc65f849a7eca04e61712"
        };

        const result = this.encrypt(data);

        const hash = CryptoJS.SHA256(JSON.stringify(data)).toString();

        console.log(result);
        console.log(hash);
    }

    static generateMessage = (uid,email) =>{
        const confirmText = "This is the confirmation that your AKTrains account has been successfully created.\n\n";
        const baseText = "Welcome to AKTrains, this email includes your account details, so please keep it safe!\n\n";
        const uidText = `\n1.Unique User Id: ${uid}`;
        const emailText = `\n\n2.Registered Email Id: ${email}`;
        const usageText = "\n\n\nRemember you will always be required to use email & password along with your unique user id mentioned above during login.";
        const disclaimer = "\n\n\n*This is an automated mail. Please do not reply to this message as this email is not monitored.";
        return `${confirmText}${baseText}${uidText}${emailText}${usageText}${disclaimer}`;
    }

    static generateMessage2 = (payload) =>{
        let reason;

        if(payload.reason==="FGPASS"){
            reason = "AKTrains account, password reset.";
        }else if(payload.reason==="RSTSYS"){
            reason= "AKTrains account, system reset. ";
        }

        const confirmText = `Let's complete your ${reason}\n\n`;
        const baseText = "Here is your eight-digit verification code.This code is valid only for 30 seconds!\n\n";
        const uidText = `\nVerification Code: ${payload.challenge}`;
        const usageText = "\n\n\nPlease enter this verification code in client app to complete the on going verification process.";
        const disclaimer = "\n\n\n*This is an automated mail. Please do not reply to this message as this email is not monitored.";
        return `${confirmText}${baseText}${uidText}${usageText}${disclaimer}`;
    }

  

    static checkSignature(document){ 
        const ogSignature = document.signature;
        delete document.signature;
        const user = jks.sort(document,true);
        const ckSignature = CryptoJS.SHA256(JSON.stringify(user)).toString();
        return ogSignature!==ckSignature;
    }
    
    static checkRateLimit(count,event){
        const timeStamp = moment(new Date()).format("YYYYMMDDTHHmmss");
        const currDate = timeStamp.substring(0,8);
        let isAllowed;

        if(count.countOf!==currDate){
            count.login=0;
            count.logout=0;
            count.challenge=0;
            count.validate=0;
            count.password=0;
            count.sysReset=0;
            count.sysCheck=0;
            count.library=0;
            count.details=0;
            count.countOf=currDate,
            count.updatedAt=timeStamp
        };


        switch (event) {

            case "login":
               isAllowed = (count.login>-1&&count.login<100);
               count.login = count.login+1;
            break;
             
            case "challenge":
                isAllowed = (count.challenge>-1&&count.challenge<100);
                count.challenge = count.challenge+1;
            break;
            case "password":
                isAllowed = (count.password>-1&&count.password<100);
                count.password = count.password+1;
            break;

            case "validate":
                isAllowed = (count.validate>-1&&count.validate<100);
                count.validate = count.validate+1;
            break; 

            case "sys-reset":
                isAllowed = (count.sysReset>-1&&count.sysReset<100);
                count.sysReset = count.sysReset+1;
            break; 

            case "sys-check":
                isAllowed = (count.sysCheck>-1&&count.sysCheck<100);
                count.sysCheck = count.sysCheck+1;
            break; 

            case "library":
                isAllowed = (count.library>-1&&count.library<100);
                count.library = count.library+1;
            break; 

            case "details":
                isAllowed = (count.details>-1&&count.details<100);
                count.details = count.details+1;
            break; 
        
            default:
                isAllowed=false;
                break;
        }

        const newCount = count;

        return {isAllowed,newCount};
    }
}

export default CustomHelperSerice;