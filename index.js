const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const cors = require("cors");
const morgan = require("morgan");

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(morgan("dev"));

// ✅ Use environment variable for Firebase service account
const serviceAccount = JSON.parse(process.env.SERVICE_ACCOUNT_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

/* ---------------- Middleware ---------------- */
// ✅ Verify Firebase ID Token
async function authenticate(req, res, next) {
  try {
    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) {
      console.warn("⚠️ No token provided");
      return res.status(401).json({ error: "No token provided" });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    console.log(`✅ Authenticated user: ${decodedToken.uid}`);
    next();
  } catch (err) {
    console.error("❌ Auth error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ✅ Check role middleware
function authorizeRole(role) {
  return async (req, res, next) => {
    try {
      const userDoc = await db.collection("users").doc(req.user.uid).get();
      if (!userDoc.exists) {
        console.warn(`⚠️ User ${req.user.uid} not found in Firestore`);
        return res.status(403).json({ error: "Not authorized" });
      }

      const userRole = userDoc.data().role;
      console.log(`👤 User ${req.user.uid} has role: ${userRole}`);

      if (userRole !== role) {
        console.warn(`🚫 Access denied for ${req.user.uid}`);
        return res.status(403).json({ error: "Not authorized" });
      }

      next();
    } catch (err) {
      console.error("❌ Role check error:", err.message);
      return res.status(500).json({ error: "Server error" });
    }
  };
}

/* ---------------- Routes ---------------- */

// ✅ Create user with role (admin only)
app.post("/createUser", authenticate, authorizeRole("admin"), async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password || !role) {
      return res.status(400).json({ error: "Email, password and role are required" });
    }

    const userRecord = await admin.auth().createUser({
      email,
      password,
      emailVerified: false,
      disabled: false,
    });

    await db.collection("users").doc(userRecord.uid).set({
      email: email,
      role: role,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log(`🎉 User created: ${email} with role ${role}`);
    res.json({ success: true, message: `User ${email} created successfully with role ${role}`, uid: userRecord.uid });
  } catch (err) {
    console.error("❌ createUser error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ Set user role (admin only)
app.post("/setRole", authenticate, authorizeRole("admin"), async (req, res) => {
  try {
    const { uid, role } = req.body;
    if (!uid || !role) {
      return res.status(400).json({ error: "uid and role required" });
    }

    await db.collection("users").doc(uid).update({ role });
    console.log(`🔑 Role of ${uid} set to ${role}`);
    res.json({ success: true, message: `Role of ${uid} set to ${role}` });
  } catch (err) {
    console.error("❌ setRole error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ Get profile (authenticated users only)
app.get("/profile", authenticate, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ uid: req.user.uid, ...userDoc.data() });
  } catch (err) {
    console.error("❌ profile error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ✅ Teacher dashboard (teacher only)
app.get("/teacher/dashboard", authenticate, authorizeRole("teacher"), (req, res) => {
  res.json({ success: true, message: "Welcome to Teacher Dashboard!" });
});

// ✅ Student dashboard (student only)
app.get("/student/dashboard", authenticate, authorizeRole("student"), (req, res) => {
  res.json({ success: true, message: "Welcome to Student Dashboard!" });
});

/* ---------------- Start Server ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
