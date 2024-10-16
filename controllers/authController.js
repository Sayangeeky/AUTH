const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const transporter = require('../config/nodemailer');
const generateOTP = require('../utils/generateOTP');
const { 
    UserSchemaZod, 
    VerifyMailSchemaZod, 
    LoginSchemaZod, 
    ForgotPasswordSchemaZod, 
    ResetPasswordSchemaZod 
} = require('../types/userValidation'); 
require('dotenv').config();
const { z } = require('zod')
// Signup Controller
exports.signup = async (req, res) => {
    const { firstName, lastName, email, password } = req.body;

    try {
        // Validate 
        UserSchemaZod.parse(req.body);

        // Check if user exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Generate OTP
        const otp = generateOTP();

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a temporary user object (not saved to DB)
        const tempUser = {
            firstName,
            lastName,
            email,
            password: hashedPassword,
            isVerified: false,
            otp,
            otpExpiration: Date.now() + 10 * 60 * 1000,
        };

        // In-memory store
        global.tempUsers = global.tempUsers || {};
        global.tempUsers[email] = tempUser;

        // Send OTP to user's email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Email Verification OTP',
            text: `Your OTP for email verification is ${otp}`,
        };

        transporter.sendMail(mailOptions, (error) => {
            if (error) {
                console.error(error);
                return res.status(500).json({ msg: 'Error sending OTP' });
            }
            res.status(200).json({ msg: 'OTP sent to email. Please verify to complete registration.' });
        });

    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ errors: err.errors });
        }
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

// Verify Mail Controller
exports.verifyMail = async (req, res) => {
    const { email, otp } = req.body;

    try {
        // Validate input with Zod
        VerifyMailSchemaZod.parse(req.body);

        const tempUser = global.tempUsers[email];

        if (!tempUser) {
            return res.status(400).json({ msg: 'Invalid Email or OTP expired' });
        }

        // Verify the provided OTP
        if (tempUser.otp !== otp) {
            return res.status(400).json({ msg: 'Invalid OTP' });
        }

        if (tempUser.otpExpiration < Date.now()) {
            delete global.tempUsers[email];
            return res.status(400).json({ msg: 'OTP Expired' });
        }

        // Create and save the new user in the database
        const newUser = new User({
            firstName: tempUser.firstName,
            lastName: tempUser.lastName,
            email: tempUser.email,
            password: tempUser.password,
            isVerified: true,
        });

        await newUser.save();
        delete global.tempUsers[email];

        res.status(200).json({ msg: 'Email verified successfully. Registration complete.' });

    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ errors: err.errors });
        }
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

// Login Controller
exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Validate 
        LoginSchemaZod.parse(req.body);

        // Check if user exists
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        // Check if user is verified
        if (!user.isVerified) {
            return res.status(400).json({ msg: 'Please verify your email first' });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        // Generate JWT
        const payload = {
            user: {
                id: user.id,
            },
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            }
        );

    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ errors: err.errors });
        }
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

// Forgot Password Controller
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        // Validate 
        ForgotPasswordSchemaZod.parse(req.body);

        // Check if user exists
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'User does not exist' });
        }

        // Generate OTP
        const otp = generateOTP();
        user.otp = otp;
        user.otpExpiration = Date.now() + 10 * 60 * 1000; 
        await user.save();

        // Send OTP via email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP for password reset is ${otp}`,
        };

        transporter.sendMail(mailOptions, (error) => {
            if (error) {
                console.error(error);
                return res.status(500).json({ msg: 'Error sending OTP' });
            }
            res.status(200).json({ msg: 'OTP sent to email' });
        });

    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ errors: err.errors });
        }
        console.error(err.message);
        res.status(500).send('Server error');
    }
};

// Reset Password Controller
exports.resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    try {
        // Validate 
        ResetPasswordSchemaZod.parse(req.body);

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid Email' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ msg: 'Invalid OTP' });
        }

        if (user.otpExpiration < Date.now()) {
            return res.status(400).json({ msg: 'OTP Expired' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);

        // Clear OTP fields
        user.otp = undefined;
        user.otpExpiration = undefined;

        await user.save();

        res.status(200).json({ msg: 'Password reset successfully' });

    } catch (err) {
        if (err instanceof z.ZodError) {
            return res.status(400).json({ errors: err.errors });
        }
        console.error(err.message);
        res.status(500).send('Server error');
    }
};
