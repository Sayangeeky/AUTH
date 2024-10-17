const express = require('express');
const connectDB = require('./config/db');
const dotenv = require('dotenv');
const authRoutes = require('./routes/authRoutes');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const cors = require('cors');

require('dotenv').config();

const app = express();
connectDB();

app.use(express.json());
app.use(helmet());
app.use(cors()); 
app.use(morgan('combined')); 

const limiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 5, 
    message: 'Too many requests, please try again later.',
});
app.use(limiter);

// Routes
app.use('/api/auth', authRoutes);

// Health Check Route
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP' });
});

// Root Endpoint
app.get('/', (req, res) => res.send('API is running'));

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error(err.stack); 
    res.status(err.status || 500).json({
        success: false,
        message: err.message || 'Server Error',
    });
});



// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}... `));
