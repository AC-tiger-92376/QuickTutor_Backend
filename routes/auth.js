const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const nodemailer = require('nodemailer');

const router = express.Router();

// Register
router.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json(error);
  }
});
const transporter = nodemailer.createTransport({
  service: 'Outlook',
  host: process.env.MAIL_HOST,
  port:  process.env.MAIL_PORT,  // TLS
  secure: false,  // Use TLS
  //service: 'outlook',  // or 'hotmail' (both use the same SMTP server)
  auth: {
    user: process.env.MAIL_USERNAME,    // your Outlook email
    pass: process.env.MAIL_PASSWORD, // your Outlook password (or App password)
  },
  tls: {
    rejectUnauthorized: false,      // Optional: Disable certificate validation (for development)
  },
});

// Route to send an email
router.post('/send-email', async (req, res) => {
  const { to, subject, text, html } = req.body;  // Extract email details from the request body

  // Set up email data
  const mailOptions = {
    from: process.env.MAIL_USERNAME,  // your email address
    to: 'philcheen@outlook.com',                           // recipient email address
    subject: subject,                 // subject of the email
    text: 'Verify',                       // plain text body
    html: "<h1>This is a test email sent from Express via SMTP.</h1>"
  };

  try {
    // Send email via Nodemailer transporter
    const info = await transporter.sendMail(mailOptions);
    res.json({ message: 'Email sent', info });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ error: 'Failed to send email', details: error });
  }
});

/*
const verifyToken = (req, res, next) => {
  
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(403).json({ message: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  
  //const token = req.headers['authorization']?.split(' ')[1]; // Extract token from 'Authorization' header
  if (!token) return res.status(403).json({ message: 'No token provided' });
  console.log("token:", token);
  // Verify token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.user = decoded; // Attach decoded user data to the request object
    next();
  });
};
*/
router.get("/user", async (req, res) => {
  
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(403).json({ message: 'No token provided' });
  }
  const token = authHeader.split(' ')[1];
  
  //const token = req.headers['authorization']?.split(' ')[1]; // Extract token from 'Authorization' header
  if (!token) return res.status(403).json({ message: 'No token provided' });
  console.log("token:", token);

  // Verify token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.user = decoded; // Attach decoded user data to the request object
    //next();
  });

  
  console.log("Decoded User:", req.user);
  try {
    //console.log('Authorization Header:', req.headers['authorization']); 
    const user = await User.findById(req.user.id);
    /*return res.status(416).json({ message: {user} });*/
    //console.log("User:", user);
    if (!user) return res.status(406).json({ message: "User not found" });

    res.json({ username: user.username, email: user.email });
  } catch (error) {
    res.status(500).json({ message: "Server error. Please try again." });
  }
});
// Login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    console.log("84"+user);
    if (!user) return res.status(409).json({ message: "User not found" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ token, user: { id: user._id, username: user.username, email: user.email } });
  } catch (error) {
    res.status(500).json(error);
  }
});

module.exports = router;
