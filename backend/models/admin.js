const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");

const AdminSchema = new mongoose.Schema(
  {
    displayName: {
      type: String,
      required: true,
      trim: true, // Removes extra whitespace
    },
    email: {
      type: String,
      required: true,
      unique: true, // Ensures no duplicate emails
      lowercase: true, // Converts to lowercase for consistency
    },
    organizationId: {
      type: String, // Admin manually enters this value
      required: true,
    },
    resetPasswordToken: {
      type: String,
      default: null, // Token for resetting password
    },
    resetPasswordExpires: {
      type: Date,
      default: null, // Expiry time for the reset token
    },
    otpSecret: {
      type: String, // Secret for 2FA
      default: null,
    },
    approvedEmails: [{ type: String }],
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt fields
  }
);

// Add passport-local-mongoose plugin to handle password management
AdminSchema.plugin(passportLocalMongoose, { usernameField: "email" });

module.exports = mongoose.model("Admin", AdminSchema);
