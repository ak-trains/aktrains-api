class CustomErrorService extends Error {

    constructor(status, msg) {
        super();
        this.status = status;
        this.message = msg;
    }


    static unAuthorizedAccess(message = "Authorization is required.") {
        return new CustomErrorService(401, message);
    }

    static forbiddenAccess(message = "Access to that resource is forbidden.") {
        return new CustomErrorService(403, message);
    }

    static resourceNotFound(message = "The requested resource was not found.") {
        return new CustomErrorService(404, message);
    }

    static conflictOccured(message = "Conflict Occured.") {
        return new CustomErrorService(409, message);
    }

    static unProcessableEntity(message = "Unprocessable Entity."){
        return new CustomErrorService(422,message);
    }

    static tooManyRequests(message = "Too many requests."){
        return new CustomErrorService(429,message);
    }

    static internalServerError(message = "There was an error on the server and the request could not be completed."){
        return new CustomErrorService(500,message);
    }

    static serverUnavailable(message = "The server is unavailable to handle this request right now."){
        return new CustomErrorService(503,message);
    }

}

export default CustomErrorService;