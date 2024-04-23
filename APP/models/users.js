
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please tell us your name!'],
    },
    email: {
        type: String,
        required: [true, "Please provide your email"],
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please provide a valid email']
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
        select: false
    },
    passwordConfirm: {
        type: String,
        required: true,
        minlength: 8,
        validate: {
            validator: function (el) {
                return el === this.password;
            },
            message: 'Passwords are not matching!'
        }
    }})
//     passwordChangedAt: Date,
//     passwordResetToken: String,
//     passwordResetExpires: Date,
//     active: {
//         type: Boolean,
//         default: true,
//         select: false
//     }
// });

// Schema method to encrypt the user's password for DB storage
// userSchema.pre('save', async function (next) {
//     if (!this.isModified('password')) return next();
//     this.password = await bcrypt.hash(this.password, 12);
//     this.passwordConfirm = undefined;
//     next();
// });

// userSchema.pre('save', function (next) {
//     if (!this.isModified('password') || this.isNew) return next();

//     this.passwordChangedAt = Date.now() - 1000;
//     next();
// });

// userSchema.pre(/^find/, function (next) {
//     this.find({ active: { $ne: false } });
//     next();
// });

// Schema method to check password validity
// userSchema.methods.correctPassword = async function (candidatePass, userPass) {
//     const result = await bcrypt.compare(candidatePass, userPass)
//     return result;
// };

// // Schema method to check if the user changed password after token was issued
// userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
//     if (this.passwordChangedAt) {
//         const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
//         return JWTTimestamp < changedTimestamp;
//     };
//     // False means password not changed
//     return false;
// };

// userSchema.methods.createPasswordResetToken = function () {
//     const resetToken = crypto.randomBytes(32).toString('hex');
//     this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
//     this.passwordResetExpires = Date.now() + 600000;
//     return resetToken;
// };

const User = mongoose.model('User', userSchema);
module.exports = User;
        
        
    

 
