var createError = require("http-errors");
var express = require("express");
var path = require("path");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const { connect } = require("mongoose");
//require("dotenv").config();
var indexRouter = require("./routes/index");
var authRouter = require("./routes/auth");
var app = express();

// view engine setup
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "jade");

app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.use("/", indexRouter);
app.use("/auth", authRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get("env") === "development" ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render("error");
});

const dbUsername = process.env.DB_USERNAME || "npc_root";
const dbPassword = process.env.DB_PASSWORD || "ImASillyPassword!";
const dbHost = process.env.DB_HOST || "mongo";
const dbPort = process.env.DB_PORT || "27017";
const dbName = process.env.DB_NAME || "NPC_Database";

//const connectionString = `mongodb://${dbUsername}:${dbPassword}@${dbHost}:${dbPort}/${dbName}`;
const connectionString = `mongodb://npc_root:ImASillyPassword!@mongo:27017/NPC_Database`;
// const connectionString =
//   "mongodb://npc_root:ImASillyPassword!@localhost:27017/NPC_Database";

connect(connectionString, {
  authSource: "admin",
})
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB: ", err.message);
  });

if (process.env.CONNECTION_STRING) {
  console.log("Connection string: " + process.env.CONNECTION_STRING);
}

module.exports = app;
