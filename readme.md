require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const redis = require('redis');
const cors = require('cors');
const helmet = require('helmet');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const mongoSanitize = require('express-mongo-sanitize');
const { Configuration, OpenAIApi } = require('openai');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const winston = require('winston');
const { body, validationResult } = require('express-validator');
const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');
const cron = require('node-cron');
const fs = require('fs');
const ejs = require('ejs');

const app = express();

// Initialize Redis for caching
const redisClient = redis.createClient();
redisClient.connect().catch((err) => console.error('Redis connection error:', err));

// Logger (Winston)
const logger = winston.createLogger({
level: 'info',
format: winston.format.combine(
winston.format.timestamp(),
winston.format.printf(({ timestamp, level, message }) => `${timestamp} [${level}]: ${message}`)
),
transports: [
new winston.transports.Console(),
new winston.transports.File({ filename: 'server.log' }),
],
});

// Middleware
app.use(bodyParser.json());
app.use(cors({ origin: process.env.FRONTEND_URL }));
app.use(helmet());
app.use(mongoSanitize());
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));

// Rate Limiting
const limiter = rateLimit({
windowMs: 15 _ 60 _ 1000,
max: 100,
message: 'Too many requests, please try again later.',
});
app.use(limiter);

// Swagger Documentation
const swaggerOptions = {
swaggerDefinition: {
openapi: '3.0.0',
info: {
title: 'Platform API',
version: '1.0.0',
description: 'Advanced API with Custom Features',
},
},
apis: ['./*.js'],
};
const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// MongoDB Connection
mongoose
.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
.then(() => logger.info('Connected to MongoDB'))
.catch((err) => logger.error(`MongoDB connection error: ${err.message}`));

// OpenAI Configuration
const openai = new OpenAIApi(new Configuration({ apiKey: process.env.OPENAI_API_KEY }));

// Mailer Configuration
const transporter = nodemailer.createTransport({
service: 'gmail',
auth: {
user: process.env.EMAIL_USER,
pass: process.env.EMAIL_PASS,
},
});

// Utility: Send Email with HTML Templates
const sendEmail = async (to, subject, templateName, templateData) => {
try {
const templatePath = `./email-templates/${templateName}.ejs`;
const template = fs.readFileSync(templatePath, 'utf8');
const html = ejs.render(template, templateData);
await transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, html });
logger.info(`Email sent to ${to}`);
} catch (err) {
logger.error(`Failed to send email to ${to}: ${err.message}`);
}
};

// MongoDB Schemas
const userSchema = new mongoose.Schema({
name: String,
email: { type: String, unique: true, index: true },
password: String,
role: { type: String, default: 'user' },
isVerified: { type: Boolean, default: false },
resetToken: String,
resetTokenExpiry: Date,
notifications: [{ type: String }], // For custom notifications
});

const platformSchema = new mongoose.Schema({
name: { type: String, required: true },
description: { type: String, required: true },
niches: [{ type: String }],
commissionRate: { type: String },
apiUrl: { type: String },
deletedAt: { type: Date, default: null },
});
platformSchema.index({ name: 1 });

const User = mongoose.model('User', userSchema);
const Platform = mongoose.model('Platform', platformSchema);

// JWT Middleware
const authenticate = (req, res, next) => {
const token = req.headers.authorization?.split(' ')[1];
if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

try {
const decoded = jwt.verify(token, process.env.JWT_SECRET);
req.user = decoded;
next();
} catch (err) {
res.status(400).json({ error: 'Invalid token.' });
}
};

const authorize = (roles) => (req, res, next) => {
if (!roles.includes(req.user.role)) {
return res.status(403).json({ error: 'Forbidden. Insufficient permissions.' });
}
next();
};

// Routes
app.post(
'/register',
[
body('name').notEmpty().withMessage('Name is required'),
body('email').isEmail().withMessage('Valid email is required'),
body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
],
async (req, res) => {
const errors = validationResult(req);
if (!errors.isEmpty()) {
return res.status(400).json({ errors: errors.array() });
}

    const { name, email, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ name, email, password: hashedPassword });
      await user.save();

      // Send verification email
      const verificationLink = `${process.env.FRONTEND_URL}/verify-email?email=${email}`;
      await sendEmail(email, 'Verify Your Email', 'verify-email', { verificationLink });

      res.status(201).json({ message: 'User registered successfully. Please verify your email.' });
    } catch (err) {
      logger.error(`Registration error: ${err.message}`);
      res.status(400).json({ error: 'User registration failed.' });
    }

}
);

// ... (Additional Routes for Admin Dashboard, Analytics, Notifications, Password Reset, etc.)
