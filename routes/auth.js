var express = require("express");
var router = express.Router();
//const ControleGear = require("../../http_server/schemas/controleGearSchema");
const User = require("../schemas/userSchema");
const ControleGear = require("../schemas/controleGearSchema");
const bcrypt = require("bcrypt");
const { sign } = require("jsonwebtoken");
const accessTokenExpirationTime = "12h";
const refreshTokenExpirationTime = "7d";
const saltRounds = 10;
const jwt = require("jsonwebtoken");

const ACCESS_TOKEN_KEY = process.env.ACCESS_TOKEN_KEY; // || "MegaSecretKeyAccessTokenKey"; //TODO Make .env file
const REFRESH_TOKEN_KEY = process.env.REFRESH_TOKEN_KEY; // || "MegaSecretKeyRefreshTokenKey"; //TODO Make .env file

function capitalizeFirstLetter(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

router.post("/signUp", async (req, res, next) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    //Check that all input is sent
    if (!(email && firstName && lastName && password)) {
      res
        .status(400)
        .send("Email, first name, last name and password is required");
    }

    console.log("email: " + email);

    const checkForExistingUser = await User.findOne({ email: email });

    if (checkForExistingUser) {
      return res.status(409).send("User already exist");
    }

    const encryptedPassword = await bcrypt.hash(password, saltRounds);

    console.log("Encrypted password: " + encryptedPassword);

    const capitalizedFirstName = capitalizeFirstLetter(firstName);
    const capitalizedLastName = capitalizeFirstLetter(lastName);

    const fullName = capitalizedFirstName + " " + capitalizedLastName;

    console.log("Full name: " + fullName);

    //create token and attach it to returned JSON
    const accessToken = sign(
      {
        email: email.toLowerCase(),
        name: fullName,
      },
      ACCESS_TOKEN_KEY,
      {
        expiresIn: accessTokenExpirationTime,
      }
    );

    // Generate refresh token
    const refreshToken = sign(
      {
        email: email.toLowerCase(),
        name: fullName,
      },
      REFRESH_TOKEN_KEY, // Store this key securely, preferably in .env
      {
        expiresIn: refreshTokenExpirationTime,
      }
    );

    let userToStore = await User.create({
      email: email.toLowerCase(),
      name: fullName,
      password: encryptedPassword,
      refreshToken: refreshToken,
    });

    console.log("User to store: " + userToStore);

    const userToReturn = {
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
    return res.status(201).json(userToReturn);
  } catch (error) {
    res.status(500).send("Could not create user");
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const toLowerCaseEmail = email.toLowerCase();
    const fetchedUser = await User.findOne({ email: toLowerCaseEmail });

    if (!fetchedUser) {
      res.status(401).json({ messages: "Invalid username or password" });
      return;
    }
    console.log(fetchedUser);

    if (await bcrypt.compare(password, fetchedUser.password)) {
      const accessToken = sign(
        {
          email: fetchedUser.email,
          name: fetchedUser.name,
        },
        ACCESS_TOKEN_KEY,
        {
          expiresIn: accessTokenExpirationTime,
        }
      );

      const refreshToken = sign(
        {
          email: fetchedUser.email,
          name: fetchedUser.name,
        },
        REFRESH_TOKEN_KEY,
        {
          expiresIn: refreshTokenExpirationTime,
        }
      );

      fetchedUser.refreshToken = refreshToken;
      await fetchedUser.save();

      const userToReturn = {
        accessToken: accessToken,
        refreshToken: refreshToken,
      };
      res.status(200).json(userToReturn);
    } else {
      res.status(401).json({ messages: "Invalid username or password" });
    }
  } catch (e) {
    res.status(500).json({ "Internal server error: ": e });
  }
});

/* GET users listing. */
router.get("/", function (req, res, next) {
  res.send("respond with a resource");
});

router.post("/addDevice", async (req, res, next) => {
  try {
    const { manufactoringID, email } = req.body;
    if (!email || !manufactoringID) {
      res
        .status(401)
        .json({ messages: "Email and manufactoringID is required" });
      return;
    }
    const fetchedUser = await User.findOne({ email: email });
    if (!fetchedUser) {
      res.status(401).json({ messages: "User does not exist" });
      return;
    }

    const checkForExistingDevice = await ControleGear.findOne({
      manufactoringID,
    });
    if (checkForExistingDevice) {
      res.status(401).json({ messages: "Device already exist" });
      return;
    }

    const refreshToken = sign(
      {
        email: fetchedUser.email,
        name: fetchedUser.name,
        manufactoringID: manufactoringID,
      },
      REFRESH_TOKEN_KEY,
      {
        expiresIn: refreshTokenExpirationTime,
      }
    );

    const accessToken = sign(
      {
        email: fetchedUser.email,
        name: fetchedUser.name,
        manufactoringID: manufactoringID,
      },
      ACCESS_TOKEN_KEY,
      {
        expiresIn: accessTokenExpirationTime,
      }
    );

    const newDevice = await ControleGear.create({
      manufactoringID,
      email,
      refreshToken,
    });
    if (!newDevice) {
      res.status(401).json({ messages: "Device not created" });
      return;
    }

    fetchedUser.controleGear.push(manufactoringID);

    await fetchedUser.save();
    if (!fetchedUser) {
      res.status(401).json({ messages: "Device not added to user" });
      return;
    }

    res
      .status(201)
      .json({ accessToken: accessToken, refreshToken: refreshToken });
  } catch (error) {
    res.status(500).send("Could not create device");
  }
});

router.post("/refreshToken_device", async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(401).json({ messages: "Refresh token is required" });
      return;
    }

    const decodedRefreshToken = jwt.verify(refreshToken, REFRESH_TOKEN_KEY);

    if (!decodedRefreshToken) {
      res.status(401).json({ messages: "Refresh token not verified" });
      return;
    }

    const fetchedControleGear = await ControleGear.findOne({
      manufactoringID: decodedRefreshToken.manufactoringID,
    });

    if (!fetchedControleGear) {
      res.status(401).json({ messages: "Invalid refresh token" });
      return;
    }
    if (fetchedControleGear.refreshToken !== refreshToken) {
      res.status(401).json({ messages: "Invalid refresh token" });
      return;
    }

    const accessToken = sign(
      {
        email: refreshToken.email,
        name: refreshToken.name,
        manufactoringID: refreshToken.manufactoringID,
      },
      ACCESS_TOKEN_KEY,
      {
        expiresIn: accessTokenExpirationTime,
      }
    );

    const newRefreshToken = sign(
      {
        email: refreshToken.email,
        name: refreshToken.name,
        manufactoringID: refreshToken.manufactoringID,
      },
      REFRESH_TOKEN_KEY,
      {
        expiresIn: refreshTokenExpirationTime,
      }
    );

    fetchedControleGear.refreshToken = newRefreshToken;
    await fetchedControleGear.save();

    if (!fetchedControleGear) {
      res.status(401).json({ messages: "Could not refresh token" });
      return;
    }

    res
      .status(201)
      .json({ accessToken: accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    res.status(500).send("Could not refresh token");
  }
});

router.post("/refreshToken_user", async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(401).json({ messages: "Refresh token is required" });
      return;
    }

    const decodedRefreshToken = jwt.verify(refreshToken, REFRESH_TOKEN_KEY);

    if (!decodedRefreshToken) {
      res.status(401).json({ messages: "Invalid refresh token" });
      return;
    }

    const user = await User.findById(decodedRefreshToken.user_id);

    if (!user) {
      res.status(401).json({ messages: "Invalid refresh token" });
      return;
    }
    if (user.refreshToken !== refreshToken) {
      res.status(401).json({ messages: "Invalid refresh token" });
      return;
    }

    const accessToken = sign(
      {
        email: refreshToken.email,
        name: refreshToken.name,
      },
      ACCESS_TOKEN_KEY,
      {
        expiresIn: accessTokenExpirationTime,
      }
    );

    const newRefreshToken = sign(
      {
        email: refreshToken.email,
        name: refreshToken.name,
      },
      REFRESH_TOKEN_KEY,
      {
        expiresIn: refreshTokenExpirationTime,
      }
    );

    user.refreshToken = newRefreshToken;
    await user.save();
    if (!user) {
      res.status(401).json({ messages: "Could not refresh token" });
      return;
    }

    res.status(201).json({ accessToken: accessToken });
  } catch (error) {
    res.status(500).send("Could not refresh token");
  }
});

module.exports = router;
