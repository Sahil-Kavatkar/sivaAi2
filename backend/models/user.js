const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const passportLocalMongoose = require("passport-local-mongoose");

const UserSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    displayName: {
        type: String,
        required: true
    },
    lastLogin: {
        type: Date,
        default: Date.now 
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    otpSecret: {  
        type: String,
        default: null  // Initially set to null if not set
    },
    organizationId: { type: String,default:null},
    token: {  
        type: String,
        default: null
    }
});

UserSchema.plugin(passportLocalMongoose, { usernameField: 'email' });
module.exports = mongoose.model('User', UserSchema);