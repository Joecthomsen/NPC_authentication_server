const mongoose = require("mongoose");
const { Schema } = mongoose;

const controleGearSchema = new Schema(
  {
    manufactoringID: {
      type: String,
      required: true,
      unique: true,
    },
    dataInstances: {
      type: [Schema.Types.ObjectId],
      default: [],
    },
  },
  {
    timestamps: true,
  }
);

// Define index on manufactoringID field
controleGearSchema.index({ manufactoringID: 1 });

const ControleGear = mongoose.model("ControleGear", controleGearSchema);
module.exports = ControleGear;
