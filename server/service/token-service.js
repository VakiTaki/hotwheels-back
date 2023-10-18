const jwt = require("jsonwebtoken");
const TokenModel = require("../models/token-model");

class TokenService {
   generateTokens(payload) {
      const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET, { expiresIn: "30m" });
      const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: "30d" });
      return { accessToken, refreshToken }
   };
   async saveTokens(id, refreshToken) {
      const tokenData = await TokenModel.findOne({ user: id });
      if (tokenData) {
         tokenData.refreshToken = refreshToken;
         return tokenData.save();
      };
      const token = await TokenModel.create({ user: id, refreshToken });
      return token;
   };
   async removeToken(refreshToken) {
      const token = await TokenModel.deleteOne({ refreshToken });
      return token;
   };
   validateAccessToken(accessToken) {
      try {
         const userData = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);
         return userData;
      } catch (error) {
         return null;
      }
   };
   validateRefreshToken(refreshToken) {
      try {
         const userData = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
         return userData;
      } catch (error) {
         return null;
      }
   };
   async findToken(refreshToken) {
      const token = await TokenModel.findOne({ refreshToken });
      return token;
   };
};

module.exports = new TokenService();