const express = require("express");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");
const morgan = require("morgan"); // ✅ Logging middleware

const app = express();
app.use(bodyParser.json());
app.use(morgan("dev")); // ✅ Logs all incoming requests (method, path, status, response time)

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
      console.warn("⚠️ No token provided");
      return res.status(401).json({ error: "No token provided" });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken; // attach user info to request
    console.log(`✅ Authenticated user: ${decodedToken.uid} (${decodedToken.email || "no email"})`);
    next();
  } catch (err) {
    console.error("❌ Auth error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// Check role of the authenticated user
function authorizeRole(role) {
  return async (req, res, next) => {
    try {
      const userDoc = await db.collection("users").doc(req.user.uid).get();
      if (!userDoc.exists) {
        console.warn(`⚠️ User ${req.user.uid} not found in Firestore`);
        return res.status(403).json({ error: "Not authorized" });
      }

      const userRole = userDoc.data().role;
      console.log(`👤 User ${req.user.uid} has role: ${userRole}, required: ${role}`);

      if (userRole !== role) {
        console.warn(`🚫 Access denied for ${req.user.uid}, role mismatch`);
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

// ✅ NEW: Create user with role (admin only)
app.post("/createUser", authenticate, authorizeRole("admin"), async (req, res) => {
  try {
    const { email, password, role } = req.body;
    
    if (!email || !password || !role) {
      console.warn("⚠️ Missing email, password, or role");
      return res.status(400).json({ error: "Email, password and role are required" });
    }

    // Create the user in Firebase Auth
    const userRecord = await admin.auth().createUser({
      email,
      password,
      emailVerified: false,
      disabled: false
    });

    // Store user role in Firestore
    await db.collection("users").doc(userRecord.uid).set({
      email: email,
      role: role,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    console.log(`🎉 User created: ${email} with role ${role}`);

    res.json({ 
      success: true, 
      message: `User ${email} created successfully with role ${role}`,
      uid: userRecord.uid 
    });
  } catch (err) {
    console.error("❌ createUser error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ Admin-only: Set role for another user
app.post("/setRole", authenticate, authorizeRole("admin"), async (req, res) => {
  try {
    const { uid, role } = req.body;
    if (!uid || !role) {
      console.warn("⚠️ Missing uid or role in setRole");
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

// ✅ Profile (any authenticated user)
app.get("/profile", authenticate, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();
    if (!userDoc.exists) {
      console.warn(`⚠️ User ${req.user.uid} profile not found`);
      return res.status(404).json({ error: "User not found" });
    }

    console.log(`📄 Profile accessed for ${req.user.uid}`);
    res.json({ uid: req.user.uid, ...userDoc.data() });
  } catch (err) {
    console.error("❌ profile error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ✅ Teacher-only route
app.get("/teacher/dashboard", authenticate, authorizeRole("teacher"), (req, res) => {
  console.log(`👨‍🏫 Teacher dashboard accessed by ${req.user.uid}`);
  res.json({ success: true, message: "Welcome to Teacher Dashboard!" });
});

// ✅ Student-only route
app.get("/student/dashboard", authenticate, authorizeRole("student"), (req, res) => {
  console.log(`🎓 Student dashboard accessed by ${req.user.uid}`);
  res.json({ success: true, message: "Welcome to Student Dashboard!" });
});

// ✅ Check admin (used by your frontend)
app.get("/checkAdmin", authenticate, async (req, res) => {
  try {
    console.log(`🔍 Checking admin for UID: ${req.user.uid}`);
    const userDoc = await db.collection("users").doc(req.user.uid).get();

    if (!userDoc.exists) {
      console.warn(`⚠️ Firestore: No record for UID ${req.user.uid}`);
      return res.status(403).json({ error: "User record missing" });
    }

    const role = userDoc.data().role;
    console.log(`👤 Firestore role for ${req.user.uid}: ${role}`);

    if (role !== "admin") {
      console.warn(`🚫 ${req.user.uid} is not admin`);
      return res.status(403).json({ error: "Not authorized" });
    }

    console.log(`✅ ${req.user.uid} verified as admin`);
    res.json({ success: true, role: "admin" });
  } catch (err) {
    console.error("❌ checkAdmin error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

/* ---------------- Start Server ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
