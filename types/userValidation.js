const { z } = require('zod');

// Schema for user signup
const UserSchemaZod = z.object({
    firstName: z.string().min(1, 'First name is required'),
    lastName: z.string().min(1, 'Last name is required'),
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    password: z.string().min(6, 'Password must be at least 6 characters long'),
});

// Schema for verifying email and OTP
const VerifyMailSchemaZod = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    otp: z.string().min(1, 'OTP is required'), // This is for verification
});

// Schema for sending OTP (only email required)
const SendOtpSchema = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'), // This is for sending OTP
});

// Schema for user login
const LoginSchemaZod = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    password: z.string().min(6, 'Password is required'),
});

// Schema for forgot password
const ForgotPasswordSchemaZod = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
});

// Schema for resetting password with OTP verification
const ResetPasswordSchemaZod = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    otp: z.string().min(1, 'OTP is required'),
    newPassword: z.string().min(6, 'New password must be at least 6 characters long'),
});

module.exports = {
    UserSchemaZod,
    VerifyMailSchemaZod,
    SendOtpSchema, 
    LoginSchemaZod,
    ForgotPasswordSchemaZod,
    ResetPasswordSchemaZod,
};
