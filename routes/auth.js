var express = require("express");
var router = express.Router();
const User = require("../schemas/userSchema");
const Controller = require("../schemas/controllerSchema");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const tokenService = require("../services/tokenService");

function capitalizeFirstLetter(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// router.post("/signUp", async (req, res, next) => {
//   try {
//     const { firstName, lastName, email, password } = req.body;

//     //Check that all input is sent
//     if (!(email && firstName && lastName && password)) {
//       res
//         .status(400)
//         .send("Email, first name, last name and password is required");
//     }

//     const emailLowerCase = email.toLowerCase();
//     const checkForExistingUser = await User.findOne({ email: emailLowerCase });

//     if (checkForExistingUser) {
//       return res.status(409).send("User already exist");
//     }

//     const encryptedPassword = await bcrypt.hash(password, saltRounds);
//     const capitalizedFirstName = capitalizeFirstLetter(firstName);
//     const capitalizedLastName = capitalizeFirstLetter(lastName);
//     const fullName = capitalizedFirstName + " " + capitalizedLastName;

//     //create token and attach it to returned JSON
//     const accessToken = tokenService.getNewAccessTokenUser(
//       emailLowerCase,
//       fullName
//     );

//     // Generate refresh token
//     const refreshToken = tokenService.getNewRefreshTokenUser(
//       emailLowerCase,
//       fullName
//     );

//     await User.create({
//       email: emailLowerCase, //email.toLowerCase(),
//       name: fullName,
//       password: encryptedPassword,
//       refreshToken: refreshToken,
//     });

//     const userToReturn = {
//       accessToken: accessToken,
//       refreshToken: refreshToken,
//       controllers: [],
//     };
//     return res.status(201).json(userToReturn);
//   } catch (error) {
//     res.status(500).send("Could not create user");
//   }
// });

// router.post("/login", async (req, res, next) => {
//   try {
//     const { email, password } = req.body;
//     const toLowerCaseEmail = email.toLowerCase();
//     const fetchedUser = await User.findOne({ email: toLowerCaseEmail });

//     if (!fetchedUser) {
//       res.status(401).json({ messages: "Invalid username or password" });
//       return;
//     }
//     console.log(fetchedUser);

//     if (await bcrypt.compare(password, fetchedUser.password)) {
//       const accessToken = tokenService.getNewAccessTokenUser(
//         fetchedUser.email,
//         fetchedUser.name
//       );

//       const refreshToken = tokenService.getNewRefreshTokenUser(
//         fetchedUser.email,
//         fetchedUser.name
//       );

//       fetchedUser.refreshToken = refreshToken;
//       await fetchedUser.save();

//       // Map the array of controller IDs to an array of promises
//       const controllerPromises = fetchedUser.controllers.map(
//         async (controllerID) => {
//           // Directly destructure the properties from the result of Controller.findOne() and return them
//           const { popID, name, controleGears } = await Controller.findOne({
//             popID: controllerID,
//           });
//           return { popID, name, controleGears };
//         }
//       );

//       // Wait for all promises to resolve using Promise.all()
//       const controllers = await Promise.all(controllerPromises);

//       const userToReturn = {
//         accessToken: accessToken,
//         refreshToken: refreshToken,
//         controllers: controllers,
//       };
//       res.status(200).json(userToReturn);
//     } else {
//       res.status(401).json({ messages: "Invalid username or password" });
//     }
//   } catch (e) {
//     res.status(500).json({ "Internal server error: ": e });
//   }
// });

// router.post("/sign_in_controller", async (req, res, next) => {
//   try {
//     const { popid, token } = req.headers;

//     console.log("HEaders: ", req.headers);

//     if (!popid) {
//       res.status(401).json({ messages: "popID header is required" });
//       return;
//     }
//     if (!token) {
//       res.status(401).json({ messages: "Token header is required" });
//       return;
//     }

//     const decodedToken = tokenService.verifyAccessTokenUser(token);
//     if (!decodedToken) {
//       res.status(401).json({ messages: "Invalid token" });
//       return;
//     }

//     const controller = await Controller.findOne({ popID: popid });
//     if (!controller) {
//       res.status(401).json({ messages: "Controller does not exist" });
//       return;
//     }

//     const accessToken = tokenService.getNewAccessTokenController(
//       controller.popID,
//       controller.name
//     );

//     const refreshToken = tokenService.getNewRefreshTokenController(
//       controller.popID,
//       controller.name
//     );

//     controller.refreshToken = refreshToken;
//     await controller.save();
//     const controllerToReturn = {
//       accessToken: accessToken,
//       refreshToken: refreshToken,
//     };
//     res.status(200).json(controllerToReturn);
//   } catch (e) {
//     res.status(500).json({ "Internal server error: ": e });
//   }
// });

// router.post("/add_controller", async (req, res, next) => {
//   try {
//     const { popID, name } = req.body;
//     const { token } = req.headers;

//     if (!popID || !name) {
//       res.status(401).json({ messages: "popID and name are required" });
//       return;
//     }
//     if (!token) {
//       res.status(401).json({ messages: "Token is required" });
//       return;
//     }

//     const decodedToken = tokenService.verifyAccessTokenUser(token);

//     if (!decodedToken) {
//       res.status(401).json({ messages: "Invalid token" });
//       return;
//     }

//     const userCount = await User.countDocuments({ email: decodedToken.email });
//     if (userCount === 0) {
//       res.status(401).json({ messages: "User does not exist" });
//       return;
//     }

//     const checkForExistingDevice = await Controller.findOne({
//       popID,
//     });

//     if (checkForExistingDevice) {
//       res.status(401).json({ messages: "Controller already exist" });
//       return;
//     }

//     const refreshToken = tokenService.getNewRefreshTokenController(popID, name);
//     const accessToken = tokenService.getNewAccessTokenController(popID, name);

//     const newDevice = await Controller.create({
//       popID,
//       name,
//       refreshToken,
//     });

//     if (!newDevice) {
//       res.status(401).json({ messages: "Device not created" });
//       return;
//     }
//     const fetchedUser = await User.findOne({ email: decodedToken.email });
//     fetchedUser.controllers.push(popID);
//     await fetchedUser.save();

//     if (!fetchedUser) {
//       res.status(401).json({ messages: "Device not added to user" });
//       return;
//     }

//     res.status(201).json({
//       controller: newDevice,
//       accessToken: accessToken,
//     });
//   } catch (error) {
//     res.status(500).send("Could not create controller");
//   }
// });

// router.post("/refresh_token_controller", async (req, res, next) => {
//   try {
//     const { refreshToken } = req.body;

//     if (!refreshToken) {
//       res.status(401).json({ messages: "Refresh token is required" });
//       return;
//     }

//     let decodedRefreshToken = "";
//     try {
//       decodedRefreshToken =
//         tokenService.verifyRefreshTokenController(refreshToken);
//     } catch (error) {
//       console.error(error);
//       res
//         .status(401)
//         .json({ messages: "Refresh token not verified: " + error });
//     }

//     if (!decodedRefreshToken) {
//       return;
//     }

//     const fetchedController = await Controller.findOne({
//       popID: decodedRefreshToken.popID,
//     });

//     if (!fetchedController) {
//       res.status(401).json({ messages: "Invalid refresh token" });
//       return;
//     }
//     if (fetchedController.refreshToken !== refreshToken) {
//       res.status(401).json({ messages: "Invalid refresh token" });
//       return;
//     }

//     const accessToken = tokenService.getNewAccessTokenController(
//       decodedRefreshToken.popID,
//       decodedRefreshToken.name
//     );

//     const newRefreshToken = tokenService.getNewRefreshTokenController(
//       decodedRefreshToken.popID,
//       decodedRefreshToken.name
//     );

//     fetchedController.refreshToken = newRefreshToken;
//     await fetchedController.save();

//     console.log(fetchedController);

//     if (!fetchedController) {
//       res.status(401).json({ messages: "Could not refresh token" });
//       return;
//     }

//     res
//       .status(201)
//       .json({ accessToken: accessToken, refreshToken: newRefreshToken });
//   } catch (error) {
//     res.status(500).send("Could not refresh token");
//   }
// });

// router.post("/refresh_token_user", async (req, res, next) => {
//   try {
//     const { refreshToken } = req.body;
//     if (!refreshToken) {
//       res.status(401).json({ messages: "Refresh token is required" });
//       return;
//     }

//     let decodedRefreshToken = tokenService.verifyRefreshTokenUser(refreshToken); //jwt.verify(refreshToken, REFRESH_TOKEN_KEY);

//     if (!decodedRefreshToken) {
//       res.status(401).json({ messages: "Invalid refresh token" });
//       return;
//     }

//     const user = await User.findOne({ email: decodedRefreshToken.email });

//     console.log(user);

//     if (!user) {
//       res.status(401).json({ messages: "Invalid refresh token" });
//       return;
//     }
//     if (user.refreshToken !== refreshToken) {
//       res.status(401).json({ messages: "Invalid refresh token" });
//       return;
//     }

//     const accessToken = tokenService.getNewAccessTokenUser(
//       decodedRefreshToken.email,
//       decodedRefreshToken.name
//     );

//     const newRefreshToken = tokenService.getNewRefreshTokenUser(
//       decodedRefreshToken.email,
//       decodedRefreshToken.name
//     );

//     user.refreshToken = newRefreshToken;
//     await user.save();
//     if (!user) {
//       res.status(401).json({ messages: "Could not refresh token" });
//       return;
//     }

//     res
//       .status(201)
//       .json({ accessToken: accessToken, refreshToken: newRefreshToken });
//   } catch (error) {
//     res.status(500).send("Could not refresh token");
//   }
// });

module.exports = router;
