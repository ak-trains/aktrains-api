import {JWT_ONLINE_SECRET,JWT_OFFLINE_SECRET, JWT_CHALLENGE_SECRET, JWT_SYSTEM_SECRET} from "../config";
import jwt from "jsonwebtoken";

class CustomJwtService {

    static signOnlineToken(payload) {
        return jwt.sign(payload, JWT_ONLINE_SECRET, { expiresIn: "60s" });
    }

    static signOfflineToken(payload) {
        return jwt.sign(payload, JWT_OFFLINE_SECRET, { expiresIn: "5d" });
    }

    static signChallengeToken(payload) {
        return jwt.sign(payload, JWT_CHALLENGE_SECRET, { expiresIn: "240s" });
    }

    static signSystemToken(payload) {
        return jwt.sign(payload, JWT_SYSTEM_SECRET, { expiresIn: "120s" });
    }

    static verifyOnlineToken(token) {
        return jwt.verify(token, JWT_ONLINE_SECRET);
    }

    static verifyOfflineToken(token) {
        return jwt.verify(token, JWT_OFFLINE_SECRET);
    }

    static verifyChallengeToken(token) {
        return jwt.verify(token, JWT_CHALLENGE_SECRET);
    }

    static verifySystemToken(token) {
        return jwt.verify(token, JWT_SYSTEM_SECRET);
    }
}

export default CustomJwtService;