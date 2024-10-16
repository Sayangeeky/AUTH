const { z } = require('zod');

const UserSchemaZod = z.object({
    firstName: z.string().min(1, 'First name is required'),
    lastName: z.string().min(1, 'Last name is required'),
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    password: z.string().min(6, 'Password must be at least 6 characters long'),
});

const VerifyMailSchemaZod = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    otp: z.string().min(1, 'OTP is required'),
});

const LoginSchemaZod = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    password: z.string().min(6, 'Password is required'),
});

const ForgotPasswordSchemaZod = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
});

const ResetPasswordSchemaZod = z.object({
    email: z.string().email('Invalid email format').min(1, 'Email is required'),
    otp: z.string().min(1, 'OTP is required'),
    newPassword: z.string().min(6, 'New password must be at least 6 characters long'),
});

module.exports = {
    UserSchemaZod,
    VerifyMailSchemaZod,
    LoginSchemaZod,
    ForgotPasswordSchemaZod,
    ResetPasswordSchemaZod,
};
