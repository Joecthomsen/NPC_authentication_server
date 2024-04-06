const mongoose = require("mongoose");
const { Schema } = mongoose;

const controllerSchema = new Schema(
  {
    popID: {
      type: String,
      required: true,
      unique: true,
    },
    name: {
      type: String,
      required: true,
      default:
        "Controller" +
        new Date().toISOString().replace(/[-T:]/g, "").slice(0, -5),
    },
    controleGears: {
      type: [String],
      default: [],
    },
    refreshToken: {
      type: String,
      required: true,
    },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

// Define index on popID field
controllerSchema.index({ popID: 1 });

const ControllerSchema = mongoose.model("ControllerSchema", controllerSchema);
module.exports = ControllerSchema;
