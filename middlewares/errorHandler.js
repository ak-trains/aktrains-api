import {DEBUG_MODE} from "../config";
import {CustomErrorService} from "../services";

const errorHandler = (err, req, res, next) => {

    let statusCode = 500;
    
    let errMsg = "Internal server error.";

    let response = {
        status:statusCode,
        data:null,
        message: errMsg,
        ...(DEBUG_MODE === 'true' && { error: err.message }),

    }
    
    if (err instanceof CustomErrorService) {

        statusCode = err.status;
        errMsg = err.message;

        if(err.status===422) errMsg = "Validation error! Unprocessable entity.";

        response = {
            status:statusCode,
            data:null,
            message: errMsg,
            ...(err.status===422 && { validations:err.message }),
        }
    }

    return res.status(statusCode).json(response);

}

export default errorHandler;