const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const port = process.env.PORT || 5000; 
const authRoutes = require("./routes/auth");

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);

// MongoDB Connection

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => app.listen(port, () => console.log("Server running on port 5000")))
  .catch((error) => console.log(error));
