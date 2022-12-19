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
            body("email").isEmail(),
            body("password").isStrongPassword(),
            body("uid").isUUID(),
        ];
    },
    register(){
        return [       
            body("fname").isAlpha().isLength({min:1,max:15}),
            body("lname").isAlpha().isLength({min:1,max:15}),
            body("email").isEmail(),
            body("password").isStrongPassword(),
            body("country").isAlpha().isLength({min:4,max:56}),
            body("secret").isAlphanumeric().isLength({min:20,max:20}),
        ];
    },
    challenge(){
        return [       
            body("email").isEmail(),
            body("uid").isUUID(),
            body("type").isAlpha(['en-US']).isLength({min:6,max:6}),
        ];
    },
    validate(){
        return [       
            body("email").isEmail(),
            body("uid").isUUID(),
            body("type").isAlpha(['en-US']).isLength({min:6,max:6}),
            body("code").isAlphanumeric(['en-US']).isLength({min:8,max:8}),
            
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
    }
}

export {validator};