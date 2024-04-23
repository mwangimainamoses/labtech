

//const { response } = require('express');
const User = require('../models/users');

const catchAsync = require('../../utilities/catchAsynchErrors')
// Sign up handler/controller
exports.signUp = catchAsync(async (req, res, next) => {

    //1. Create the new user in the DB
    const newUser = (await User.create(req.body));
    const url = `${req.protocol}://${req.get('host')}/me`;
    await new Email(newUser, url).sendWelcome();

    //2. If everything is ok, send token to client
    const token = signToken(newUser._id);

    const cookieOptions = {
        maxAge: process.env.COOKIE_EXPIRES_IN,
        httpOnly: true
    };
    if (process.env.NODE_ENV === 'prod') cookieOptions.secure = true;

    // Sending the token via cookie
    res.cookie('jwt', token, cookieOptions);

    //Remove password from the response
    newUser.password = undefined;

    // Send back the sign up response to the client
    res.status(201).json({
        statusCode: '00',
        statusMessage: 'User created successfully',
        successful: true,
        responseObject: {
            user: newUser,
            token: token,
        }
    })

});

////////
//const User = require('../models/users')
//const multer = require('multer');
//const sharp = require('sharp');

// const catchAsync = require('./../utilities/catchAsyncError');
// const AppError = require('./../utilities/appErrors');
// const factory = require('./handlerFactory');

// // IMAGE UPLOAD HANDLER
// const multerStorage = multer.memoryStorage();

// const multerFilter = (req, file, callback) => {
//     if (file.mimetype.startsWith('image')) {
//         callback(null, true)
//     } else {
//         callback(new AppError('File is not an image! Please upload images only', 400), false)
//     }
// }

// const upload = multer({
//     storage: multerStorage,
//     fileFilter: multerFilter
// });

// exports.uploadUserPhoto = upload.single('photo');

//IMAGE PROCESSING MIDDLEWARE
// exports.resizeUserPhoto = catchAsync(async (req, res, next) => {
//     if (!req.file) return next();

//     req.file.filename = `user-${req.user.id}-${Date.now()}.jpeg`;

//     await sharp(req.file.buffer)
//         .resize(500, 500)
//         .toFormat('jpeg')
//         .jpeg({ quality: 90 })
//         .toFile(`public/img/users/${req.file.filename}`);

//     next();
// });

// const filterBody = (body, ...allowedFields) => {
//     const newObj = {};
//     Object.keys(body).forEach(el => {
//         if (allowedFields.includes(el)) {
//             newObj[el] = body[el]
//         }
//     })
//     return newObj;
// };

//ROUTE HANDLERS
// exports.getMyDetails = catchAsync(async (req, res, next) => {
//     req.params.id = req.user.id;
//     next();
// });

// exports.updateMyDetails = catchAsync(async (req, res, next) => {

//     //1. Create an error if user tries to update password
//     if (req.body.password || req.body.passwordConfirm) {
//         return next(new AppError('This endpoint is not for password updates. Please use /change-my-password instead', 400));
//     }

//     //2. Filter out unwanted fields that are not allowed to be updated e.g role
//     const filteredBody = filterBody(req.body, 'name', 'email');
//     if (req.file) filteredBody.photo = req.file.filename;

//     //3. Update user data in the DB
//     const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
//         new: true,
//         runValidators: true
//     }).select('-__v');

//     //4. Send back update result to the client
//     res.status(200).json({
//         statusCode: '00',
//         statusMessage: 'Your details have been updated successfully',
//         successful: true,
//         responseObject: {
//             user: updatedUser
//         }
//     })
// });

// exports.deleteMyAccount = catchAsync(async (req, res, next) => {
//     await User.findByIdAndUpdate(req.user.id, {
//         active: false
//     })

//     res.status(200).json({
//         statusCode: '00',
//         statusMessage: 'User successfully deleted',
//         successful: true
//     })
// });

// exports.getAllUsers = factory.getAllItems(User);
// exports.getUserById = factory.getItemById(User);
// exports.updateUser = factory.updateItem(User);
// exports.deleteUser = factory.deleteItem(User);