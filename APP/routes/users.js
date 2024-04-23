const router = require('express').Router();
const userController = require('../controllers/users');
const authController = require('../controllers/authController')




router.post('/signup', authController.signUp);

module.exports = router;