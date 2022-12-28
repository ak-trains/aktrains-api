const IN_ELIGIBLE_TO_SIGNUP = "You are not eligible for creating account. Please make sure that you have purchased atleast one addon from AKTrains before creating account. If you have already purchased then please wait for our confirmation mail.";
const EMAIL_ALREADY_EXISTS = "A user with AKTrains account for provided email address already exists. Please provide a different email address";
const UID_ALREADY_EXISTS = "A user with AKTrains account for generated user id already exits. Please try again after some time.";
const REGISTER_SUCCESS = "Welcome to AKTrains! Your account has been successfully created. Please check your inbox, a email including your account details has been sent to registered email address.";
const BAD_CREDENTIALS = "Credentials provided by you are wrong/invalid. Please check your credentials and try again.";
const BANNED_USER_ACCOUNT = "You are banned from AKTrains because you have violated our terms of service. If you think it's a mistake or you want to know more, contact AKTrains.";
const TAMPERED_USER_DATA = "Login not allowed temporarily, need account check. It seems like your account profile has information which fails to validate its integrity. Contact AKTrains for more information.";
const CHALLENGE_SENT = "An email containing eight-digit one time verification code has been sent to your registered email address.";
const BAD_CHALLENGE_TYPE = "Since provided challenge type in invalid, therefore failed to generate one time verification code. Please try again later";
const CHALLENGE_EXPIRED = "Verification code provided by you is expired. Please generate a new verification code and try again.";
const INSUFFICIENT_PRIVILEGES = "You do not have the level of access to perform the task you requested. Please try again with proper authorization."
const BAD_AUTHORIZATION = "Authorization token provided by you is wrong/invalid. Please try again with valid authorization token.";
const PASSWORD_RESET_SUCCESS = "Awesome, you have successfully updated your password. Now that you're yourself again, check if your account data is correct by signing in again.";
const VERIFICATION_SUCCESS = "Woah you did it. Your identity is verified successfully and you can now proceed ahead.";
export {
    IN_ELIGIBLE_TO_SIGNUP,
    EMAIL_ALREADY_EXISTS,
    REGISTER_SUCCESS,
    UID_ALREADY_EXISTS,
    BAD_CREDENTIALS,
    BANNED_USER_ACCOUNT,
    TAMPERED_USER_DATA,
    CHALLENGE_SENT,
    BAD_CHALLENGE_TYPE,
    CHALLENGE_EXPIRED,
    INSUFFICIENT_PRIVILEGES,
    BAD_AUTHORIZATION,
    PASSWORD_RESET_SUCCESS,
    VERIFICATION_SUCCESS,
}