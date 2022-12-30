const PROTECTED_RESOURCE = "Unauthorized access of protected resource. Failed to verify the identity of requesting end.";
const UNSUPPORTED_CLIENT= "This version of client app is no longer supported. Please download the latest version to continue.";
const UNDER_MAINTAINANCE = "Sorry for the inconvinience. The server is currently undergoing a scheduled maintainance.";
const ACCESS_DENIED = "Either you are not logged in or you do not have permission to perform this action/use this service.";
const INSUFFICIENT_PRIVILEGES = "You do not have the level of access to perform the action you requested. Please try again with valid authorization.";
const TAMPERED_DATA = "Failed to validate your account. Your account contains information which fails to validate its integrity.";
const BAD_AUTHORIZATION = "Authorization provided is either expired or has failed to verify it's identity. Please try again with valid authorization.";
const USER_NOT_FOUND = "A user with AKTrains account for the provided user ID and email address could not be found. Try again with valid credentials.";
const QUOTA_EXPIRED = "We limit how often you can perform or do certian actions on AKTrains to protect our systems. You can try again later.";
const TOO_MANY_REQUESTS = "We are sorry, but you have sent too many requests to us recently. Please try again later. That's all we can say.";
const ATTEMPTS_EXPIRED = "You reached maximum number of attempts to perform this action and hence being blocked temporarliy from performing this action. Try again after some time.";
const BAD_CREDENTIALS = "Credentials provided by you are invalid. Please check your credentials correctly and try again.";
const BANNED_USER_ACCOUNT = "You are banned from AKTrains because you have violated our terms of service. If you think it's a mistake, contact AKTrains.";
const ALREADY_LOGGED_IN = "You are already logged in elsewhere. You can only be logged in on one system at a time. Log out from other system and try again.";
const IN_ELIGIBLE_TO_SIGNUP = "You are not eligible for creating account. Please make sure that you have purchased atleast one addon from AKTrains before creating account. If you have already purchased then please wait for our confirmation mail.";
const EMAIL_ALREADY_EXISTS = "A user with AKTrains account for provided email address already exists. Please provide a different email address";
const UID_ALREADY_EXISTS = "A user with AKTrains account for generated user id already exits. Please try again after some time.";
const BAD_CHALLENGE_TYPE = "Since provided challenge type in invalid, therefore failed to perform desired action. Please try again later";
const CHALLENGE_EXPIRED = "Verification code provided by you is expired. Please generate a new verification code and try again.";
const SAME_PASSWORD = "Your new password cannot be the same as your old password. Try again with a different password.";
const TAMPERED_SYSTEM = "Failed to validate your system. Your system information fails to validate its integrity.";
const ALREADY_CHALLENGED = "You have already requested for a verification code which is not yet used by you. Either wait for it to expire or use it.";
const SAME_SYSTEM = "Your new system cannot be the same as your old system. Try again if with a different system.";
const NEW_SYSTEM_DETECTED = "Account login on an unrecognized device is detected. You can only use app on one system at a time. Either use app on recognized system or get new system registered.";
const INTERNAL_SERVER_ERROR = "The server encountered an error and could not complete your request. If problem persists, then please contact AKTrains.";
const LOGIN_SUCCESS= "Well done, you have logged in successfully.";
const REGISTER_SUCCESS = "Welcome to AKTrains! Your account has been successfully created. Please check your inbox, a email including your account details has been sent to registered email address.";
const CHALLENGE_SENT = "An email containing eight-digit one time verification code has been sent to your registered email address.";
const VERIFICATION_SUCCESS = "Woah you did it. Your identity is verified successfully and you can now proceed ahead.";
const PASSWORD_RESET_SUCCESS = "Awesome, you have successfully updated your password. Now that you're yourself again, check if your account data is correct by signing in again.";
const SYSTEM_RESET_SUCCESS = "Awesome, you have successfully updated your system details. Now that you're yourself again, check if your account data is correct by signing in again.";
const LOGOUT_SUCCESS= "Well done, you have logged out successfully.";

export {
    PROTECTED_RESOURCE,
    UNSUPPORTED_CLIENT,
    UNDER_MAINTAINANCE,
    ACCESS_DENIED,
    INSUFFICIENT_PRIVILEGES,
    TAMPERED_DATA,
    BAD_AUTHORIZATION,
    USER_NOT_FOUND,
    QUOTA_EXPIRED,
    TOO_MANY_REQUESTS,
    ATTEMPTS_EXPIRED,
    BAD_CREDENTIALS,
    BANNED_USER_ACCOUNT,
    ALREADY_LOGGED_IN,
    IN_ELIGIBLE_TO_SIGNUP,
    EMAIL_ALREADY_EXISTS,
    UID_ALREADY_EXISTS,
    BAD_CHALLENGE_TYPE,
    CHALLENGE_EXPIRED,
    SAME_PASSWORD,
    TAMPERED_SYSTEM,
    ALREADY_CHALLENGED,
    SAME_SYSTEM,
    NEW_SYSTEM_DETECTED,
    LOGIN_SUCCESS,
    REGISTER_SUCCESS,
    CHALLENGE_SENT,
    INTERNAL_SERVER_ERROR,
    VERIFICATION_SUCCESS,
    PASSWORD_RESET_SUCCESS,
    SYSTEM_RESET_SUCCESS,
    LOGOUT_SUCCESS,
}