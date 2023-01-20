import {body,header} from "express-validator";

const validator = {
    apiAuth(){
        return [
            header("secret","Invalid request header.").isString().isLength({max:256,min:256}),
            header("signature","Invalid request header.").isHash("sha256"),
        ]
    },
    userAuth(){
        return [
            header("authorization","Invalid request header.").isJWT(),
        ];
    },
    login(){
        return[
            body("email","Invalid email address.").isEmail(),
            body("password","Invalid password. Required (minimum of 8 chars ,1 uppercase, 1 lowercase, 1 digit & 1 special char).").isStrongPassword(),
            body("uid","Invalid user ID.").isUUID(),
        ];
    },
    register(){
        return [       
            body("fname","Invalid First name.").isAlpha().isLength({min:1,max:15}),
            body("lname","Invalid Last name.").isAlpha().isLength({min:1,max:15}),
            body("email","Invalid email address.").isEmail(),
            body("password","Invalid password. Required (minimum of 8 chars ,1 uppercase, 1 lowercase, 1 digit & 1 special char).").isStrongPassword(),
            body("country","Invalid country.").isAlpha().isLength({min:4,max:56}),
            body("secret","Invalid registration key.").isString().isLength({min:20,max:20}),
        ];
    },
    challenge(){
        return [       
            body("email","Invalid email address.").isEmail(),
            body("uid","Invalid user ID.").isUUID(),
            body("type","Invalid challenge type.").isAlpha(['en-US']).isLength({min:6,max:6}),
        ];
    },
    validate(){
        return [       
            body("email","Invalid email address.").isEmail(),
            body("uid","Invalid user ID.").isUUID(),
            body("type","Invalid challenge type.").isAlpha(['en-US']).isLength({min:6,max:6}),
            body("code","Invalid verification code.").isAlphanumeric(['en-US']).isLength({min:8,max:8}),
            
        ];
    },
    password(){
        return[
            body("password").isStrongPassword(),
        ];
    },
    system(){
        return [
            body("system").isJWT(),
        ]
    },
}

export {validator};