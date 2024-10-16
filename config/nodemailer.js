
const nodemailer = require('nodemailer');
require('dotenv').config()
const transporter = nodemailer.createTransport({
    host: process.env.HOST,
    port: 587,
    secure: false, 
    auth: {
        user: process.env.USER,
        pass: process.env.PASS,
    },
    tls: {
        rejectUnauthorized: false 
    }
});

module.exports = transporter;
