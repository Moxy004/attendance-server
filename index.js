const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// ✅ Use the environment variable instead of JSON file
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

/* ---------------- Middleware ---------------- */
// Verify Firebase ID Token
async function authenticate(req, res, next) {
  try {
    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) {
      return res.status(401).json({ error: "No token provided" });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken; // attach user info to request
    next();
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Check role of the authenticated user
async function authorizeRole(role) {
  return async (req, res, next) => {
    try {
      const userDoc = await db.collection("users").doc(req.user.uid).get();
      if (!userDoc.exists || userDoc.data().role !== role) {
        return res.status(403).json({ error: "Not authorized" });
      }
      next();
    } catch (err) {
      console.error("Role check error:", err);
      return res.status(500).json({ error: "Server error" });
    }
  };
}

/* ---------------- Routes ---------------- */

// ✅ Admin-only: Set role for another user
app.post("/setRole", authenticate, authorizeRole("admin"), async (req, res) => {
  try {
    const { uid, role } = req.body;
    if (!uid || !role) {
      return res.status(400).json({ error: "uid and role required" });
    }

    await db.collection("users").doc(uid).update({ role });
    res.json({ success: true, message: `Role of ${uid} set to ${role}` });
  } catch (err) {
    console.error("setRole error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ Example protected route for all authenticated users
app.get("/profile", authenticate, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();
    if (!userDoc.exists) return res.status(404).json({ error: "User not found" });

    res.json({ uid: req.user.uid, ...userDoc.data() });
  } catch (err) {
    console.error("profile error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ✅ Example teacher-only route
app.get("/teacher/dashboard", authenticate, authorizeRole("teacher"), (req, res) => {
  res.json({ success: true, message: "Welcome to Teacher Dashboard!" });
});

// ✅ Example student-only route
app.get("/student/dashboard", authenticate, authorizeRole("student"), (req, res) => {
  res.json({ success: true, message: "Welcome to Student Dashboard!" });
});

/* ---------------- Start Server ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
