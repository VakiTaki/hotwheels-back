const UserModel = require("../models/user-model");
const bcrypt = require("bcrypt");
const uuid = require("uuid");
const mailService = require("../service/mail-service");
const tokenService = require("../service/token-service");
const UserDto = require("../dtos/user-dto");
const ApiError = require("../exceptions/api-error");

class UserService {
   async registration(email, password, phone) {
      const candidat = await UserModel.findOne({ email });
      if (candidat) {
         throw ApiError.BadRequest("Пользователь с такой почтой уже существует")
      };
      const hashPassword = await bcrypt.hash(password, 3);
      const activationLink = uuid.v4();
      const user = await UserModel.create({ email, password: hashPassword, activationLink, phone });
      await mailService.sendActivationMail(email, `${process.env.API_URL}api/activate/${activationLink}`);
      const userDto = new UserDto(user);
      const tokens = tokenService.generateTokens({ ...userDto });
      await tokenService.saveTokens(userDto.id, tokens.refreshToken);
      return {
         ...tokens,
         user: userDto
      }
   };
   async activate(activationLink) {
      const user = await UserModel.findOne({ activationLink });
      if (!user) { throw ApiError.BadRequest("Неверная ссылка активации") };
      user.isActivated = true;
      await user.save();
   };
   async login(email, password) {
      const user = await UserModel.findOne({ email });
      if (!user) {
         throw ApiError.BadRequest("Пользователь не найден");
      };
      const isPassEquals = await bcrypt.compare(password, user.password);
      if (!isPassEquals) {
         throw ApiError.BadRequest("Неверный пароль");
      };
      const userDto = new UserDto(user);
      const tokens = tokenService.generateTokens({ ...userDto });
      await tokenService.saveTokens(userDto.id, tokens.refreshToken);
      return {
         ...tokens,
         user: userDto
      }
   };
   async logout(refreshToken) {
      const token = await tokenService.removeToken(refreshToken);
      return token;
   };
   async refresh(refreshToken) {
      if (!refreshToken) {
         throw ApiError.UnavtorizeError();
      }
      const userData = tokenService.validateRefreshToken(refreshToken);
      const tokenFromDb = await tokenService.findToken();
      if (!userData && !tokenFromDb) {
         throw ApiError.UnavtorizeError();
      };
      const user = await UserModel.findById(userData.id);
      const userDto = new UserDto(user);
      const tokens = tokenService.generateTokens({ ...userDto });
      await tokenService.saveTokens(userDto.id, tokens.refreshToken);
      return {
         ...tokens,
         user: userDto
      }
   };
   async getAllUsers() {
      const users = UserModel.find();
      return users;
   };
}

module.exports = new UserService();