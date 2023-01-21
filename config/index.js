import dotenv from "dotenv";
import admin from "firebase-admin";

dotenv.config();

const serviceAccountCreds = {
    "type": process.env.TYPE,
    "project_id": process.env.PROJECT_ID,
    "private_key_id": process.env.PRIVATE_KEY_ID,
    "private_key": process.env.PRIVATE_KEY.replace(/\\n/g, '\n'),
    "client_email": process.env.CLIENT_EMAIL,
    "client_id": process.env.CLIENT_ID,
    "auth_uri": process.env.AUTH_URI,
    "token_uri": process.env.TOKEN_URI,
    "auth_provider_x509_cert_url": process.env.AUTH_PROVIDER_X509_CERT_URL,
    "client_x509_cert_url": process.env.CLIENT_X509_CERT_URL
};


admin.initializeApp({
    credential:admin.credential.cert(serviceAccountCreds),
    databaseURL:process.env.DATABASE_URL,
});

const DB = admin.database();

const APP_PORT = process.env.PORT||3000;

export{APP_PORT,DB}

export const {
    JWT_ONLINE_SECRET,
    JWT_OFFLINE_SECRET,
    JWT_CHALLENGE_SECRET,
    JWT_SYSTEM_SECRET,
    DEBUG_MODE,
    MAINTAINANCE_MODE,
    MAIL_USERNAME,
    MAIL_PASSWORD,
    CLIENT_APP_KEY,
    CLIENT_APP_ID,
    CLIENT_APP_VER,
    CRYPT_KEY,
    WIDTIME,
    MAXREQ
} = process.env;