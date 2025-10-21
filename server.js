import { APP_PORT } from "./config/index.js";
import { errorHandler } from "./middlewares/index.js";
import express from "express";
import routes from "./routes/index.js";
import { validator } from "./validators/index.js";
import { CustomErrorService } from "./services/index.js";
import rateLimit from "express-rate-limit";  // Note: Use default import for consistency
import { TOO_MANY_REQUESTS } from "./constants/index.js";

const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const limiter = rateLimit({
  windowMs: 1000,  // 1 second window
  max: 1,  // 1 request per window
  handler: (req, res, next, optionsUsed) => {
    return next(CustomErrorService.tooManyRequests(TOO_MANY_REQUESTS));
  },
});

app.use("/", limiter, validator.apiAuth()(apiHandler, routes));  // Assuming apiHandler is from middlewares
app.use(errorHandler);

app.listen(APP_PORT, () => console.log(`Listening on port ${APP_PORT}`));
