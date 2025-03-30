const express = require("express");
const Admin = require("../models/admin"); // Correct path to Admin model
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const authMiddleware = require("../middleware/authMiddleware"); // Vérifie le bon chemin d'import
const router = express.Router();

// Exemple de données pour les statistiques (cela doit venir de votre base de données dans un cas réel)
const statistics = {
  totalUsers: 100,
  totalExercises: 200,
  activeUsers: 50,
};

// Exemple de données pour les activités récentes
const recentActivities = [
  { user: 'User1', action: 'Logged in', timestamp: '2023-03-26 12:30' },
  { user: 'User2', action: 'Completed exercise', timestamp: '2023-03-26 12:45' },
];

// Route pour obtenir les statistiques
router.get('/admin-statistics', authMiddleware, (req, res) => {
  res.json(statistics); // Vous pouvez remplacer cela par des données provenant de la base de données
});

// Route pour obtenir les activités récentes
router.get('/recent-activities', authMiddleware, (req, res) => {
  res.json(recentActivities); // Remplacez par des données provenant de la base de données
});

// Signup Route
router.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if admin already exists
    const adminExists = await Admin.findOne({ email });
    if (adminExists) {
      return res.status(400).json({ message: "Admin already exists" });
    }

    // Hash the password before saving
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create a new admin with hashed password
    const newAdmin = new Admin({ email, password: hashedPassword });
    await newAdmin.save();

    res.status(201).json({ message: "Admin created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Login Route
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find admin by email
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign({ id: admin._id, email: admin.email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // Log the token to check if it's generated properly
    console.log("Generated token:", token);

    res.json({ token });
  } catch (error) {
    console.error("Error during login:", error); // Log the error
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
