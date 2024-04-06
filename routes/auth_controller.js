var express = require("express");
//import { Request, Response, NextFunction } from "express";
const tokenService = require("../services/tokenService");
const User = require("../schemas/userSchema");
const Controller = require("../schemas/controllerSchema");
const bcrypt = require("bcrypt");
const saltRounds = 10;
var router = express.Router();

router.post("/sign_in", async (req, res, next) => {
  try {
    const { popid, token } = req.headers;

    console.log("HEaders: ", req.headers);

    if (!popid) {
      res.status(401).json({ messages: "popID header is required" });
      return;
    }
    if (!token) {
      res.status(401).json({ messages: "Token header is required" });
      return;
    }

    const decodedToken = tokenService.verifyAccessTokenUser(token);
    if (!decodedToken) {
      res.status(401).json({ messages: "Invalid token" });
      return;
    }

    const controller = await Controller.findOne({ popID: popid });
    if (!controller) {
      res.status(401).json({ messages: "Controller does not exist" });
      return;
    }

    const accessToken = tokenService.getNewAccessTokenController(
      controller.popID,
      controller.name
    );

    const refreshToken = tokenService.getNewRefreshTokenController(
      controller.popID,
      controller.name
    );

    controller.refreshToken = refreshToken;
    await controller.save();
    const controllerToReturn = {
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
    res.status(200).json(controllerToReturn);
  } catch (e) {
    res.status(500).json({ "Internal server error: ": e });
  }
});

router.post("/add_controller", async (req, res, next) => {
  try {
    const { popID, name } = req.body;
    const { token } = req.headers;

    if (!popID || !name) {
      res.status(401).json({ messages: "popID and name are required" });
      return;
    }
    if (!token) {
      res.status(401).json({ messages: "Token is required" });
      return;
    }

    const decodedToken = tokenService.verifyAccessTokenUser(token);

    if (!decodedToken) {
      res.status(401).json({ messages: "Invalid token" });
      return;
    }

    const user = await User.findOne({ email: decodedToken.email });
    if (!user) {
      res.status(401).json({ messages: "User does not exist" });
      return;
    }

    const checkForExistingDevice = await Controller.findOne({
      popID,
    });

    if (checkForExistingDevice) {
      //const index = user.controllers.findIndex((controller) => controller === popID);

      // Controller found, remove it from the array
      const existingUser = await User.findById(checkForExistingDevice.owner);
      if (existingUser) {
        const index = existingUser.controllers.indexOf(
          checkForExistingDevice.popID
        );
        if (index !== -1) {
          existingUser.controllers.splice(index, 1);
          await existingUser.save();
        }

        user.controllers.push(popID); // Add the new controller to the user's controllers array
        await user.save(); // Save the updated user document
        checkForExistingDevice.owner = user._id; // Update the owner of the existing device
        res.status(200).json({ message: "Controller relocated successfully" });
      } else {
        // Controller not found in the array
        res
          .status(404)
          .json({ message: "Controller not found in user's array" });
      }
      //res.status(401).json({ messages: "Controller already exist" });
      return;
    }

    const refreshToken = tokenService.getNewRefreshTokenController(popID, name);
    const accessToken = tokenService.getNewAccessTokenController(popID, name);

    const newDevice = await Controller.create({
      popID,
      name,
      refreshToken,
      owner: user._id,
    });

    if (!newDevice) {
      res.status(401).json({ messages: "Device not created" });
      return;
    }
    const fetchedUser = await User.findOne({ email: decodedToken.email });
    fetchedUser.controllers.push(popID);
    await fetchedUser.save();

    if (!fetchedUser) {
      res.status(401).json({ messages: "Device not added to user" });
      return;
    }

    res.status(201).json({
      controller: newDevice,
      accessToken: accessToken,
    });
  } catch (error) {
    res.status(500).send("Could not create controller");
  }
});

router.post("/refresh_token", async (req, res, next) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      res.status(401).json({ messages: "Refresh token is required" });
      return;
    }

    let decodedRefreshToken = "";
    try {
      decodedRefreshToken =
        tokenService.verifyRefreshTokenController(refreshToken);
    } catch (error) {
      console.error(error);
      res
        .status(401)
        .json({ messages: "Refresh token not verified: " + error });
    }

    if (!decodedRefreshToken) {
      return;
    }

    const fetchedController = await Controller.findOne({
      popID: decodedRefreshToken.popID,
    });

    if (!fetchedController) {
      res.status(401).json({ messages: "Invalid refresh token" });
      return;
    }
    if (fetchedController.refreshToken !== refreshToken) {
      res.status(401).json({ messages: "Invalid refresh token" });
      return;
    }

    const accessToken = tokenService.getNewAccessTokenController(
      decodedRefreshToken.popID,
      decodedRefreshToken.name
    );

    const newRefreshToken = tokenService.getNewRefreshTokenController(
      decodedRefreshToken.popID,
      decodedRefreshToken.name
    );

    fetchedController.refreshToken = newRefreshToken;
    await fetchedController.save();

    console.log(fetchedController);

    if (!fetchedController) {
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

module.exports = router;
