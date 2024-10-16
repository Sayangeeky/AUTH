const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/auth');

// Signup Route
router.post('/signup', authController.signup);

// Verify email Route
router.post('/verify-mail', authController.verifyMail);

// Login Route
router.post('/login', authController.login);

// Forgot Password Route
router.post('/forgot-password', authController.forgotPassword);

// Reset Password Route
router.post('/reset-password', authController.resetPassword);

module.exports = router;
