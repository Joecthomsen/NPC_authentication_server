const { sign, verify } = require("jsonwebtoken");
const accessTokenExpirationTimeUser = "12h";
const refreshTokenExpirationTimeUser = "7d";
const accessTokenExpirationTimeController = "12h";
const refreshTokenExpirationTimeController = "7d";

const ACCESS_TOKEN_KEY_USER =
  process.env.ACCESS_TOKEN_KEY || "MegaSecretKeyAccessTokenKeyUser"; //TODO Make .env file
const REFRESH_TOKEN_KEY_USER =
  process.env.REFRESH_TOKEN_KEY || "MegaSecretKeyRefreshTokenKeyUser"; //TODO Make .env file
const ACCESS_TOKEN_KEY_CONTROLLER =
  process.env.ACCESS_TOKEN_KEY_CONTROLLER ||
  "MegaSecretKeyAccessTokenKeyController"; //TODO Make .env file
const REFRESH_TOKEN_KEY_CONTROLLER =
  process.env.REFRESH_TOKEN_KEY_CONTROLLER ||
  "MegaSecretKeyRefreshTokenKeyController"; //TODO Make .env file

const getNewAccessTokenUser = (email, name) => {
  const accessToken = sign(
    {
      email: email,
      name: name,
    },
    ACCESS_TOKEN_KEY_USER,
    {
      expiresIn: accessTokenExpirationTimeUser,
    }
  );
  return accessToken;
};

const getNewRefreshTokenUser = (email, name) => {
  const refreshToken = sign(
    {
      email: email,
      name: name,
    },
    REFRESH_TOKEN_KEY_USER,
    {
      expiresIn: refreshTokenExpirationTimeUser,
    }
  );
  return refreshToken;
};

const getNewAccessTokenController = (popID, name) => {
  const accessToken = sign(
    {
      name: name,
      popID: popID,
    },
    ACCESS_TOKEN_KEY_CONTROLLER,
    {
      expiresIn: accessTokenExpirationTimeController,
    }
  );
  return accessToken;
};

const getNewRefreshTokenController = (popID, name) => {
  const refreshToken = sign(
    {
      name: name,
      popID: popID,
    },
    REFRESH_TOKEN_KEY_CONTROLLER,
    {
      expiresIn: refreshTokenExpirationTimeController,
    }
  );
  return refreshToken;
};

const verifyAccessTokenUser = (token) => {
  try {
    const decodedToken = verify(token, ACCESS_TOKEN_KEY_USER);
    return decodedToken;
  } catch (err) {
    return false;
  }
};

const verifyRefreshTokenUser = (token) => {
  try {
    const decodedToken = verify(token, REFRESH_TOKEN_KEY_USER);
    return decodedToken;
  } catch (err) {
    return false;
  }
};

const verifyAccessTokenController = (token) => {
  try {
    const decodedToken = verify(token, ACCESS_TOKEN_KEY_CONTROLLER);
    return decodedToken;
  } catch (err) {
    return false;
  }
};

const verifyRefreshTokenController = (token) => {
  try {
    const decodedToken = verify(token, REFRESH_TOKEN_KEY_CONTROLLER);
    return decodedToken;
  } catch (err) {
    return false;
  }
};

module.exports = {
  getNewAccessTokenUser,
  getNewRefreshTokenUser,
  getNewAccessTokenController,
  getNewRefreshTokenController,
  verifyAccessTokenUser,
  verifyRefreshTokenUser,
  verifyAccessTokenController,
  verifyRefreshTokenController,
};
