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

// Example: protected route to set user role
app.post("/setRole", async (req, res) => {
  try {
    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) return res.status(401).json({ error: "No token provided" });

    // Verify Firebase ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Check if requester is admin
    const requesterDoc = await db.collection("users").doc(decodedToken.uid).get();
    if (!requesterDoc.exists || requesterDoc.data().role !== "admin") {
      return res.status(403).json({ error: "Not authorized" });
    }

    // Set role of target user
    const { uid, role } = req.body;
    await db.collection("users").doc(uid).update({ role });

    res.json({ success: true, message: `Role of ${uid} set to ${role}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
