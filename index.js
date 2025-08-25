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

/* ---------------- Helper Functions ---------------- */
// ✅ Check if an admin already exists
async function adminExists() {
  const snapshot = await db.collection("users").where("role", "==", "admin").get();
  return !snapshot.empty;
}

/* ---------------- Routes ---------------- */

// ✅ Create user with role (admin only)
app.post("/createUser", authenticate, authorizeRole("admin"), async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: "Name, email, password, and role are required" });
    }

    const normalizedRole = role.toLowerCase();

    // 🚫 Block creating another admin if one already exists
    if (normalizedRole === "admin" && (await adminExists())) {
      return res.status(403).json({ error: "Only one admin is allowed" });
    }

    let existingUser;
    try {
      existingUser = await admin.auth().getUserByEmail(email);
    } catch (err) {
      existingUser = null;
    }

    if (existingUser) {
      return res.status(400).json({ error: "This email is already registered!" });
    }

    // ✅ Create new Firebase Auth user
    const userRecord = await admin.auth().createUser({
      email,
      password,
      emailVerified: false,
      disabled: false,
    });

    // ✅ Save user in Firestore
    await db.collection("users").doc(userRecord.uid).set({
      name,
      email,
      role: normalizedRole,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(201).json({
      success: true,
      message: `✅ User ${email} created successfully`,
      uid: userRecord.uid,
    });
  } catch (err) {
    console.error("❌ Error creating user:", err.message);

    if (err.code === "auth/email-already-exists") {
      return res.status(400).json({ error: "This email is already registered!" });
    }

    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ✅ Set user role (admin only)
app.post("/setRole", authenticate, authorizeRole("admin"), async (req, res) => {
  try {
    const { uid, role } = req.body;
    if (!uid || !role) {
      return res.status(400).json({ error: "uid and role required" });
    }

    const normalizedRole = role.toLowerCase();

    // 🚫 Prevent assigning "admin" role if one already exists
    if (normalizedRole === "admin" && (await adminExists())) {
      return res.status(403).json({ error: "An admin already exists" });
    }

    await db.collection("users").doc(uid).update({ role: normalizedRole });
    console.log(`🔑 Role of ${uid} set to ${normalizedRole}`);
    res.json({ success: true, message: `Role of ${uid} set to ${normalizedRole}` });
  } catch (err) {
    console.error("❌ setRole error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ✅ Check if the logged-in user is the ONLY admin
app.get("/checkAdmin", authenticate, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();

    if (!userDoc.exists) {
      return res.status(403).json({ error: "User not found" });
    }

    const userData = userDoc.data();

    // ✅ Only allow access if the role is "admin"
    if (userData.role !== "admin") {
      console.warn(`🚫 Access denied for ${req.user.uid}`);
      return res.status(403).json({ error: "Not authorized" });
    }

    res.json({ success: true, message: "✅ Admin verified" });
  } catch (err) {
    console.error("❌ checkAdmin error:", err.message);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ✅ Get all users (admin only)
app.get("/getUsers", authenticate, authorizeRole("admin"), async (req, res) => {
  try {
    const snapshot = await db.collection("users").orderBy("createdAt", "desc").get();
    const users = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.json({ success: true, users });
  } catch (err) {
    console.error("❌ getUsers error:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ✅ Fix missing roles for old users (optional)
app.get("/fixRoles", async (req, res) => {
  try {
    const snapshot = await db.collection("users").get();
    const updates = [];

    snapshot.forEach(doc => {
      const data = doc.data();
      if (!data.role) {
        updates.push(
          db.collection("users").doc(doc.id).update({ role: "student" })
        );
      }
    });

    await Promise.all(updates);
    res.json({ success: true, message: "✅ Fixed missing roles" });
  } catch (err) {
    console.error("❌ fixRoles error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ---------------- Start Server ---------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
