const ApiError = require("../exceptions/api-error");
const tokenService = require("../service/token-service");

module.exports = function (req, res, next) {
   try {
      const authorizationHeader = req.headers.authorization;
      console.log(authorizationHeader);
      if (!authorizationHeader) {
         return next(ApiError.UnavtorizeError());
      };
      const accessToken = authorizationHeader.split(" ")[1];
      if (!accessToken) { return next(ApiError.UnavtorizeError()) }
      const userData = tokenService.validateAccessToken(accessToken);
      if (!userData) { return next(ApiError.UnavtorizeError()) };
      req.user = userData;
      next();
   } catch (error) {
      return next(ApiError.UnavtorizeError());
   }
}