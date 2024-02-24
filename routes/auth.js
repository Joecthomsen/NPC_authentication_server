var express = require('express');
var router = express.Router();
//const User = require('../../http_server/schemas/userSchema');
const User = require('../schemas/userSchema');
const bcrypt = require("bcrypt");
const {sign} = require("jsonwebtoken");
const tokenExpirationTime = "15h"
const saltRounds = 10;

const ACCESS_TOKEN_KEY = "MegaSecretKeyAccessTokenKey"  //TODO Make .env file

function capitalizeFirstLetter(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

router.post('/signUp', async (req, res, next) => {
  try {
    const {firstName, lastName, email, password} = req.body

    //Check that all input is sent
    if(!(email && firstName && lastName && password)){
        res.status(400).send("Email, first name, last name and password is required")
    }

    console.log("email: " + email)

    const checkForExistingUser = await User.findOne({email: email})

    if(checkForExistingUser){
        return res.status(409).send("User already exist")
    }

    console.log("TEST")


    const encryptedPassword = await bcrypt.hash(password, saltRounds)

    console.log("Encrypted password: " + encryptedPassword)

    const capitalizedFirstName = capitalizeFirstLetter(firstName);
    const capitalizedLastName = capitalizeFirstLetter(lastName);

    const fullName = capitalizedFirstName + " " + capitalizedLastName;

    console.log("Full name: " + fullName)


    let userToStore = await User.create({
        email: email.toLowerCase(),
        name: fullName,
        password: encryptedPassword
    })

    console.log("User to store: "+userToStore)

    //create token and attach it to returned JSON
    userToStore.token = sign(
        {user_id: userToStore._id, email: userToStore.email, name: userToStore.name},
            ACCESS_TOKEN_KEY,
        {
            expiresIn: tokenExpirationTime,
        }
    )

    const createdUser = await User.findByIdAndUpdate(userToStore._id, { ...userToStore }, {new: true})
    console.log(createdUser)

    const userToReturn = {
        token: createdUser.token,
    }
    return (
        res.status(201).json(userToReturn)
    )
} catch (error) {
    res.status(500).send("Could not create user")
}
})

router.post('/login', async (req, res, next) => {
    try{
        const {email, password} = req.body
        const toLowerCaseEmail = email.toLowerCase()
        const fetchedUser = await User.findOne({email: toLowerCaseEmail})

        if(!fetchedUser){
            res.status(401).json({"messages": "Invalid username or password"})
            return
        }
        console.log(fetchedUser)

        if(await bcrypt.compare(password, fetchedUser.password)){
            console.log("TEST")
            fetchedUser.token = sign(
                {user_id: fetchedUser._id, email: fetchedUser.email, name: fetchedUser.name},
                ACCESS_TOKEN_KEY,
                {
                    expiresIn: tokenExpirationTime,
                }
            )

            const userToReturn = {
                token: fetchedUser.token,
            }
            res.status(200).json(userToReturn)
        }
        else {
            res.status(401).json({"messages": "Invalid username or password"})
        }


    }catch (e) {
        res.status(500).json({"Internal server error: ":e})
    }
})

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

module.exports = router;
