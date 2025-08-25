const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const cors = require("cors");
const morgan = require("morgan");

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(morgan("dev"));

// 🔹 Load Firebase Service Account
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

/* ---------------- Authentication Middleware ---------------- */
async function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      console.log("⚠️ No token found in request");
      return res.status(401).json({ error: "Missing token" });
    }

    const token = authHeader.split("Bearer ")[1];
    console.log(`🔑 Token received: ${token.substring(0, 20)}...`);

    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;

    console.log(`✅ Authenticated UID: ${decodedToken.uid}`);
    next();
  } catch (error) {
    console.error("❌ AUTH ERROR:", error.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

/* ---------------- Role-based Authorization ---------------- */
function authorizeRole(role) {
  return async (req, res, next) => {
    try {
      const userDoc = await db.collection("users").doc(req.user.uid).get();
      if (!userDoc.exists) {
        console.log(`⚠️ No user record found for ${req.user.uid}`);
        return res.status(403).json({ error: "User not found" });
      }

      const userRole = userDoc.data().role;
      console.log(`👤 UID: ${req.user.uid} | Role: ${userRole} | Required: ${role}`);

      if (userRole !== role) {
        console.log(`🚫 Access denied for ${req.user.uid}`);
        return res.status(403).json({ error: "Access denied" });
      }

      next();
    } catch (err) {
      console.error("❌ ROLE ERROR:", err.message);
      return res.status(500).json({ error: "Server error" });
    }
  };
}

/* ---------------- Routes ---------------- */

// ✅ Debug endpoint → See your current user & role
app.get("/debug", authenticate, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();
    const userData = userDoc.exists ? userDoc.data() : null;

    res.json({
      uid: req.user.uid,
      email: req.user.email,
      firestore: userData,
    });
  } catch (err) {
    console.error("❌ DEBUG ERROR:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ✅ Protected admin route
app.get("/admin/dashboard", authenticate, authorizeRole("admin"), (req, res) => {
  res.json({ success: true, message: "Welcome Admin!" });
});

// ✅ Protected teacher route
app.get("/teacher/dashboard", authenticate, authorizeRole("teacher"), (req, res) => {
  res.json({ success: true, message: "Welcome Teacher!" });
});

// ✅ Protected student route
app.get("/student/dashboard", authenticate, authorizeRole("student"), (req, res) => {
  res.json({ success: true, message: "Welcome Student!" });
});

/* ---------------- Start Server ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
