const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");
const multer = require('multer'); // Used for handling file uploads
const fs = require('fs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require("pg");
require("dotenv").config(); // Load environment variables

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Set up basic middleware in correct order
app.use(cookieParser());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json());

// CORS setup
app.use(cors({
    origin: ["https://misscal.net", "https://www.misscal.net"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));

// Define public paths that don't need authentication
const PUBLIC_PATHS = [
    "/login",
    "/signup",
    "/forgot-password",
    "/reset-password"
];

// Serve static files (should come before auth middleware)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/photos", express.static(path.join(__dirname, "uploads")));
app.use(express.static(path.join(__dirname, 'public')));

// Handle OPTIONS requests for CORS
app.use((req, res, next) => {
    if (req.method === "OPTIONS") {
        return res.sendStatus(200);
    }
    next();
});

// SINGLE authentication middleware - REMOVE ALL OTHER auth checks
app.use((req, res, next) => {
    // Check if the path should be publicly accessible
    if (PUBLIC_PATHS.includes(req.path)) {
        return next();
    }

    // Skip auth for static file paths
    if (req.path.startsWith('/uploads/') || req.path.startsWith('/photos/')) {
        return next();
    }

    // If we get here, authentication is required
    if (!req.cookies || !req.cookies.user_id) {
        return res.status(401).json({ message: "Unauthorized: Please log in." });
    }

    next();
});

// Email transporter setup
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "mikejamesma23248@gmail.com",
        // For Gmail, you'll need to create an App Password in your Google Account
        pass: "eepw sstx qlmo sgts" // Replace with your app password
    }
});

// Database setup
const db = new Pool({
    connectionString: "postgresql://neondb_owner:npg_N3jhmKgHalk6@ep-little-cell-a6siaqa3-pooler.us-west-2.aws.neon.tech/neondb?sslmode=require",
    ssl: {
        rejectUnauthorized: false,
    },
});

// Verify database connection
db.connect()
    .then(() => console.log("✅ Connected to Neon PostgreSQL database."))
    .catch((err) => {
        console.error("❌ Database connection error:", err);
        process.exit(1);
    });

// Set up multer for file uploads
const upload = multer({
    dest: 'uploads/',
    limits: { files: 10 }
});
app.post("/submitForm", upload.array("photos", 10), (req, res) => {
    res.header("Access-Control-Allow-Origin", "https://www.misscal.net");  // Set only your frontend domain
    res.header("Access-Control-Allow-Credentials", "true");  // Allow credentials (cookies, auth headers)
    res.header("Access-Control-Allow-Methods", "POST");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");

    const {
        user_id,
        name,
        major,
        gpa,
        campaign_line,
        personal_story,
        experience,
        organizations,
        instagram,
        year,
        linkedin,
        facebook,
        github,
        snapchat,
        tiktok,
        form_submitted,
    } = req.body;

    const photos = req.files.map((file) => file.path);

    if (!user_id) {
        return res.status(400).json({ message: "User ID is required." });
    }

    const queryCheckUser = "SELECT form_submitted FROM Users WHERE user_id = $1";
    db.query(queryCheckUser, [user_id], (err, userResults) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({message: "Database error."});
        }

        if (userResults.rows.length === 0) {
            return res.status(400).json({message: "User not found."});
        }

        if (userResults.rows[0].form_submitted) {
            return res.status(400).json({message: "You have already submitted your participation form. One person can only upload information once."});
        }

        // Check if the user already exists in the database
        const queryCheck = "SELECT * FROM ContestEntries WHERE user_id = $1";
        db.query(queryCheck, [user_id], (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({message: "Database error."});
            }


            if (results.length > 0) {
                // User exists, selectively update their data
                const existingData = results[0];


                const fieldsToUpdate = {};
                const valuesToUpdate = [];

                // Compare each field and only add changed values to the update query
                if (major && major !== existingData.major) {
                    fieldsToUpdate.major = "?";
                    valuesToUpdate.push(major);
                }
                if (name && name !== existingData.name) {
                    fieldsToUpdate.name = "?";
                    valuesToUpdate.push(name);
                }
                if (gpa && gpa !== existingData.gpa) {
                    fieldsToUpdate.gpa = "?";
                    valuesToUpdate.push(gpa);
                }
                if (gpa && gpa !== existingData.year) {
                    fieldsToUpdate.year = "?";
                    valuesToUpdate.push(year);
                }
                if (campaign_line && campaign_line !== existingData.campaign_line) {
                    fieldsToUpdate.campaign_line = "?";
                    valuesToUpdate.push(campaign_line);
                }
                if (personal_story && personal_story !== existingData.personal_story) {
                    fieldsToUpdate.personal_story = "?";
                    valuesToUpdate.push(personal_story);
                }
                if (experience && experience !== existingData.experience) {
                    fieldsToUpdate.experience = "?";
                    valuesToUpdate.push(experience);
                }
                if (organizations && organizations !== existingData.organizations) {
                    fieldsToUpdate.organizations = "?";
                    valuesToUpdate.push(organizations);
                }
                if (instagram && instagram !== existingData.instagram) {
                    fieldsToUpdate.instagram = "?";
                    valuesToUpdate.push(instagram);
                }
                if (linkedin && linkedin !== existingData.linkedin) {
                    fieldsToUpdate.linkedin = "?";
                    valuesToUpdate.push(linkedin);
                }
                if (facebook && facebook !== existingData.facebook) {
                    fieldsToUpdate.facebook = "?";
                    valuesToUpdate.push(facebook);
                }
                if (github && github !== existingData.github) {
                    fieldsToUpdate.github = "?";
                    valuesToUpdate.push(github);
                }
                if (snapchat && snapchat !== existingData.snapchat) {
                    fieldsToUpdate.snapchat = "?";
                    valuesToUpdate.push(snapchat);
                }
                if (tiktok && tiktok !== existingData.tiktok) {
                    fieldsToUpdate.tiktok = "?";
                    valuesToUpdate.push(tiktok);
                }
                if (photos.length > 0 && JSON.stringify(photos) !== existingData.photos) {
                    fieldsToUpdate.photos = "?";
                    valuesToUpdate.push(JSON.stringify(photos));
                }

                // If no fields to update, return success immediately
                if (Object.keys(fieldsToUpdate).length === 0) {
                    return res.status(200).json({message: "No changes detected. Nothing to update."});
                }

                // Construct the dynamic update query
                const setClause = Object.keys(fieldsToUpdate)
                    .map((key) => `${key} = ${fieldsToUpdate[key]}`)
                    .join(", ");

                fieldsToUpdate.form_submitted = "$" + (valuesToUpdate.length + 1);
                valuesToUpdate.push(true);

                const queryUpdate = `UPDATE ContestEntries
                                     SET ${setClause}
                                     WHERE user_id = $1`;
                valuesToUpdate.push(user_id); // Add user_id to the end of the query values

                db.query(queryUpdate, valuesToUpdate, (err, results) => {
                    if (err) {
                        console.error("Database error:", err);
                        return res.status(500).json({message: "Database error."});
                    }
                    res.status(200).json({message: "Contest entry updated successfully!"});
                });
            } else {
                // User does not exist, insert new data
                const queryInsert = `
                    INSERT INTO ContestEntries (user_id, major, gpa, name, campaign_line, personal_story, experience,
                                                organizations,
                                                instagram, linkedin, facebook, github, snapchat, tiktok, photos,
                                                form_submitted, year)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                `;
                db.query(
                    queryInsert,
                    [
                        user_id,
                        major,
                        gpa || null,
                        name,
                        campaign_line,
                        personal_story,
                        experience,
                        organizations,
                        instagram,
                        linkedin,
                        facebook,
                        github,
                        snapchat,
                        tiktok,
                        JSON.stringify(photos),
                        true,
                        year || null,
                    ],
                    (err, results) => {
                        if (err) {
                            console.error("Database error:", err);
                            return res.status(500).json({message: "Database error."});
                        }
                        const queryUpdateUser = `UPDATE Users
                                                 SET form_submitted = true
                                                 WHERE user_id = $1`;
                        db.query(queryUpdateUser, [user_id], (err) => {
                            if (err) {
                                console.error("Database error:", err);
                                return res.status(500).json({message: "Database error."});
                            }
                            res.status(201).json({message: "Contest entry created successfully!"});
                        });
                    }
                );
            }
        });
    });
});
// Signup Endpoint
//const { sendVerificationEmail } = require("../sendVerificationEmail");
//const { generateVerificationToken } = require("../generateVerificationToken");

// POST /submitForm


// For demonstration, assume you have a 'Users' table with fields:
//    full_name, email, password, is_verified (TINYINT), email_verification_token (VARCHAR)
app.post("/signup", async (req, res) => {
    const { full_name, email, password } = req.body;

    if (!full_name || !email || !password) {
        return res.status(400).json({ message: "All fields are required." });
    }

    // e.g., if you require a certain domain
    if (!email.endsWith("@berkeley.edu")) {
        return res.status(400).json({ message: "Email must be a UC Berkeley email." });
    }

    // 1) Check if email exists
    const queryCheckEmail = "SELECT email FROM Users WHERE email = $1";
    db.query(queryCheckEmail, [email], async (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.rows.length > 0) {
            return res.status(409).json({ message: "Email already exists." });
        }

        // 2) Generate token & hashed password (in memory)
        //const verificationToken = generateVerificationToken();
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password, 10);
        } catch (hashErr) {
            console.error("Error hashing password:", hashErr);
            return res.status(500).json({ message: "Internal server error." });
        }

        // 3) Attempt to send the email *before* inserting user into DB
        //try {
         //   await sendVerificationEmail(email, verificationToken);
        ///} catch (mailErr) {
        //    console.error("Error sending verification email:", mailErr);
            // If we fail here, we do *not* insert the user
        //    return res.status(500).json({ message: "Failed to send verification email." });
       // }

        // 4) If email sent successfully, now insert user with is_verified=0
        const queryInsert = `
      INSERT INTO Users (full_name, email, password, is_verified)
      VALUES ($1, $2, $3, $4)
      
    `;

        //db.query(queryInsert, [full_name, email, hashedPassword, verificationToken, false], (err, insertResults) => {
        db.query(queryInsert, [full_name, email, hashedPassword, false], (err, insertResults) => {
            if (err) {
                console.error("Database insertion error:", err);
                return res.status(500).json({ message: "Database error." });
            }

            // 5) Respond success; user is in DB with is_verified=0
            res.status(201).json({
                message: "Signup successful! Please check your email to verify."
            });
        });
    });
});
app.get("/verify-email", (req, res) => {
    const { token } = req.query;
    if (!token) {
        return res.status(400).send("Missing token.");
    }

    const selectQuery = "SELECT user_id FROM Users WHERE email_verification_token = ?";
    db.query(selectQuery, [token], (err, results) => {
        if (err) {
            console.error("DB error:", err);
            return res.status(500).send("Database error.");
        }
        if (results.length === 0) {
            return res.status(400).send("Invalid or expired token.");
        }

        const userId = results[0].user_id;
        const updateQuery = `
      UPDATE Users
      SET is_verified = false, email_verification_token = NULL
      WHERE user_id = ?
    `;
        db.query(updateQuery, [userId], (err) => {
            if (err) {
                console.error("DB error (update):", err);
                return res.status(500).send("Error verifying user in DB.");
            }
            // Optionally redirect or show success page
            res.send("Email verified! You can now log in.");
        });
    });
});


app.post("/logout", (req, res) => {
    res.clearCookie("user_id", { path: "/" }); // ✅ Remove the user_id cookie
    res.status(200).json({ message: "Logged out successfully!" });
});
// Login Endpoint
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required." });
    }

    const query = "SELECT * FROM Users WHERE email = $1";
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (!results.rows || results.rows.length === 0) {
            return res.status(404).json({ message: "Email not found." });
        }

        const user = results.rows[0];

        try {
            const isPasswordCorrect = await bcrypt.compare(password, user.password);
            if (!isPasswordCorrect) {
                return res.status(401).json({ message: "Incorrect password." });
            }

            // ✅ Explicitly set the HTTP-only, Secure cookie for HTTPS
            res.cookie("user_id", user.user_id, {
                httpOnly: true,
                secure: true,  // ✅ Required for HTTPS
                sameSite: "None", // ✅ Must be None for cross-origin requests
                path: "/",
            });

            console.log("✅ Cookie Set: user_id =", user.user_id);

            res.status(200).json({
                message: "Login successful!",
                user: { id: user.user_id, full_name: user.full_name, email: user.email },
            });

        } catch (error) {
            console.error("Password comparison error:", error);
            return res.status(500).json({ message: "Internal server error." });
        }
    });
});


app.get("/getProfile", (req, res) => {
    const userId = req.cookies.user_id;
    console.log("Received user_id from cookie:", userId);

    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const query = "SELECT * FROM ContestEntries WHERE user_id = $1";
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.rows.length === 0) {
            console.log("No profile found for user_id:", userId);
            return res.status(404).json({ message: "Profile not found." });
        }

        let profile = results.rows[0];

        // Ensure photos is parsed correctly
        if (profile.photos && Array.isArray(profile.photos)) {
            //profile.photos = profile.photos.map(photo => `${photo}`);
        } else {
            profile.photos = [];
        }



        console.log("Final profile photos:", profile.photos);
        res.json(profile);
    });
});



app.post("/updateProfile", upload.single("photo"), (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    // Extract text fields from request body
    const {
        name, major, gpa, campaign_line, personal_story,
        experience, organizations, instagram, linkedin,
        facebook, github, snapchat, tiktok, year
    } = req.body;

    // Prepare fields for update
    const fieldsToUpdate = {
        name, major, gpa, campaign_line, personal_story,
        experience, organizations, instagram, linkedin,
        facebook, github, snapchat, tiktok, year
    };

    // Convert "None" values to empty strings
    for (const field in fieldsToUpdate) {
        if (fieldsToUpdate[field] === 'None') {
            fieldsToUpdate[field] = '';
        }
    }

    // Check if a new photo was uploaded
    let photoPath = req.file ? req.file.path : null;

    // Retrieve existing photos
    const getPhotosQuery = "SELECT photos FROM ContestEntries WHERE user_id = $1";
    db.query(getPhotosQuery, [userId], (err, result) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        let existingPhotos = [];
        if (result.rows.length > 0 && result.rows[0].photos) {
            try {
                existingPhotos = Array.isArray(result.rows[0].photos) ? result.rows[0].photos : JSON.parse(result.rows[0].photos);
            } catch (error) {
                console.error("Error parsing existing photos:", error);
            }
        }

        // Update only the first image (replace previous profile picture)
        if (photoPath) {
            existingPhotos[0] = photoPath; // Replace first photo
        }

        // Filter out undefined or empty fields
        const validFields = Object.entries(fieldsToUpdate).filter(([_, value]) => value !== undefined && value !== "");

        if (photoPath) {
            validFields.push(["photos", JSON.stringify(existingPhotos)]);
        }

        if (validFields.length === 0) {
            return res.status(400).json({ message: "No fields to update." });
        }

        // Construct dynamic UPDATE query for PostgreSQL
        const setClause = validFields.map(([key], index) => `${key} = $${index + 1}`).join(", ");
        const queryParams = validFields.map(([_, value]) => value);
        queryParams.push(userId);

        const queryUpdate = `UPDATE ContestEntries SET ${setClause} WHERE user_id = $${queryParams.length}`;

        db.query(queryUpdate, queryParams, (err, results) => {
            if (err) {
                console.error("Database error:", err);
                return res.status(500).json({ message: "Database error." });
            }
            res.json({ message: "Profile updated successfully!", photo: existingPhotos[0] });
        });
    });
});


// Get Student Details Route
app.get("/getStudentDetails", (req, res) => {
    const userId = req.cookies.user_id;

    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const query = `
        SELECT name, major, gpa, campaign_line, personal_story,
               experience, organizations, photos,
               instagram, linkedin, facebook, github, tiktok
        FROM ContestEntries
        WHERE user_id = $1
    `;

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (!results.rows || results.rows.length === 0) {
            return res.status(404).json({ message: "Student not found." });
        }

        const student = results.rows[0];

        let photo = "";
        let photosArray = [];

        try {
            if (
                student.photos &&
                typeof student.photos === "string" &&
                student.photos.trim().startsWith("[")
            ) {
                photosArray = JSON.parse(student.photos);
            }
            photo = photosArray.length > 0
                ? `https://server1.misscal.net/${photosArray[0]}`
                : "";
        } catch (error) {
            console.error("Error parsing photos:", error);
            photo = "";
        }

        res.json({
            name: student.name,
            major: student.major,
            gpa: student.gpa,
            campaign_line: student.campaign_line,
            personal_story: student.personal_story,
            experience: student.experience,
            organizations: student.organizations,
            photo,
            instagram: student.instagram,
            linkedin: student.linkedin,
            facebook: student.facebook,
            github: student.github,
            tiktok: student.tiktok,
        });
    });
});




app.get("/getStudent", (req, res) => {
    const loggedInUserId = req.cookies.user_id;
    const requestedUserId = req.query.userId; // Get userId from the query parameter

    if (!loggedInUserId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    // If no userId specified in query, default to the logged-in user
    const userIdToLookup = requestedUserId || loggedInUserId;

    const query = "SELECT name, major, gpa, campaign_line, personal_story, experience, organizations, photos, instagram, linkedin, facebook, github, tiktok, year FROM ContestEntries WHERE user_id = $1";

    db.query(query, [userIdToLookup], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.rows.length === 0) {
            return res.status(404).json({ message: "Student not found." });
        }

        const student = results.rows[0];

        // Process photos - handle both array and string formats
        let photo = "";
        try {
            if (typeof student.photos === 'string') {
                const photosArray = JSON.parse(student.photos || "[]");
                photo = photosArray.length > 0 ? photosArray[0] : "";
            } else if (Array.isArray(student.photos)) {
                photo = student.photos.length > 0 ? student.photos[0] : "";
            }
        } catch (error) {
            console.error("Error parsing photos:", error);
            photo = "";
        }

        res.json({
            name: student.name,
            major: student.major,
            gpa: student.gpa,
            year: student.year,
            campaign_line: student.campaign_line,
            personal_story: student.personal_story,
            experience: student.experience,
            organizations: student.organizations,
            photo,
            instagram: student.instagram,
            linkedin: student.linkedin,
            facebook: student.facebook,
            github: student.github,
            tiktok: student.tiktok,
        });
    });
});
app.get("/getStudentDetails", (req, res) => {
    const userId = req.cookies.user_id;

    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const query = "SELECT name, major, gpa, campaign_line, personal_story, experience, organizations, photos, instagram, linkedin, facebook, github, tiktok, year FROM ContestEntries WHERE user_id = $1";
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "Student not found." });
        }

        const student = results[0];
        const photo = JSON.parse(student.photos || "[]")[0] || "";

        res.json({
            name: student.name,
            major: student.major,
            gpa: student.gpa,
            year: student.year,
            campaign_line: student.campaign_line,
            personal_story: student.personal_story,
            experience: student.experience,
            organizations: student.organizations,
            photo,
            instagram: student.instagram,
            linkedin: student.linkedin,
            facebook: student.facebook,
            github: student.github,
            tiktok: student.tiktok,
        });
    });
});

app.get("/getDetails", (req, res) => {
    const userId = req.cookies.user_id;

    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const query = "SELECT name, major, gpa, campaign_line, personal_story, experience, organizations, photos, instagram, linkedin, facebook, github, tiktok, year FROM ContestEntries WHERE user_id = $1";

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        // For PostgreSQL using Pool, results are in rows property
        if (!results.rows || results.rows.length === 0) {
            return res.status(404).json({ message: "Student not found." });
        }

        const student = results.rows[0];

        // Safely handle photos data
        let photoArray = [];
        let mainPhoto = "";

        try {
            if (student.photos) {
                // Handle both string and array formats
                if (typeof student.photos === "string") {
                    photoArray = JSON.parse(student.photos);
                } else if (Array.isArray(student.photos)) {
                    photoArray = student.photos;
                }

                // Filter out null/undefined/empty values
                photoArray = photoArray.filter(photo => photo);

                // Get first photo as main photo
                if (photoArray.length > 0) {
                    mainPhoto = photoArray[0];
                }
            }
        } catch (error) {
            console.error("Error parsing photos:", error);
            photoArray = [];
            mainPhoto = "";
        }

        // Respond with the data
        res.json({
            name: student.name || "",
            major: student.major || "",
            gpa: student.gpa || "",
            year: student.year || "",
            campaign_line: student.campaign_line || "",
            personal_story: student.personal_story || "",
            experience: student.experience || "",
            organizations: student.organizations || "",
            photos: photoArray, // Send the full array of photos
            photo: mainPhoto,   // Send the main photo separately
            instagram: student.instagram || "",
            linkedin: student.linkedin || "",
            facebook: student.facebook || "",
            github: student.github || "",
            tiktok: student.tiktok || ""
        });
    });
});

app.get("/searchStudents", (req, res) => {
    const query = req.query.query; // Get the search query from the client

    if (!query) {
        return res.status(400).json({ message: "Search query is required." });
    }

    const sqlQuery = `
        SELECT *
        FROM ContestEntries
        WHERE name LIKE $1 OR major LIKE $2
    `;

    db.query(sqlQuery, [`%${query}%`, `%${query}%`], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.rows.length === 0) {
            return res.status(404).json({ message: "No students found." });
        }

        const students = results.rows.map(student => {
            // Debug all possible photo fields in the database
            console.log(`Student ${student.name} photo data:`, {
                photo: student.photo,
                photos: student.photos,
                uploads: student.uploads
            });

            // Try to find the photo in various possible fields
            let photoUrl = "/default-photo.jpg"; // Default fallback

            // Check each possible field where the photo URL might be stored
            if (student.uploads && Array.isArray(student.uploads) && student.uploads.length > 0) {
                // If it's stored in an 'uploads' field as an array
                photoUrl = `/uploads/${student.uploads[0]}`;
            } else if (student.uploads && typeof student.uploads === 'string') {
                // If 'uploads' is a string
                try {
                    // Try parsing it as JSON
                    const parsedUploads = JSON.parse(student.uploads);
                    if (Array.isArray(parsedUploads) && parsedUploads.length > 0) {
                        photoUrl = `/uploads/${parsedUploads[0]}`;
                    } else {
                        photoUrl = `/uploads/${student.uploads}`;
                    }
                } catch (e) {
                    // If it's not JSON, use it directly
                    photoUrl = `/uploads/${student.uploads}`;
                }
            } else if (student.photo_url) {
                // If there's a direct photo_url field
                photoUrl = student.photo_url;
            } else if (student.photo) {
                // If there's a photo field
                photoUrl = student.photo;
            }

            // Ensure the URL is properly formatted
            if (photoUrl && !photoUrl.startsWith('http') && !photoUrl.startsWith('/')) {
                photoUrl = '/' + photoUrl;
            }

            return {
                userId: student.user_id,
                name: student.name,
                major: student.major,
                gpa: student.gpa,
                year: student.year,
                personal_story: student.personal_story,
                campaign_line: student.campaign_line,
                experience: student.experience,
                organizations: student.organizations,
                instagram: student.instagram,
                linkedin: student.linkedin,
                facebook: student.facebook,
                github: student.github,
                tiktok: student.tiktok,
                snapchat: student.snapchat,
                photo: photoUrl
            };
        });

        res.json(students);
    });
});

app.get("/getCurrentStudent", (req, res) => {
    const userId = req.cookies.user_id;

    if (!userId) {
        return res.status(401).json({ message: "Unauthorized. Please log in first." });
    }

    const sqlQuery = `
        SELECT *
        FROM ContestEntries
        WHERE user_id = $1
    `;

    db.query(sqlQuery, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.rows.length === 0) {
            return res.status(404).json({ message: "Student profile not found." });
        }

        const student = results.rows[0];

        // ✅ No need to parse, treat as string
        let photoUrl = `https://server1.misscal.net/${student.photos}`;



        const studentData = {
            userId: student.user_id,
            name: student.name,
            major: student.major,
            gpa: student.gpa,
            year: student.year,
            personal_story: student.personal_story,
            campaign_line: student.campaign_line,
            experience: student.experience,
            organizations: student.organizations,
            instagram: student.instagram,
            linkedin: student.linkedin,
            facebook: student.facebook,
            github: student.github,
            tiktok: student.tiktok,
            photo: photoUrl
        };

        res.json(studentData);
    });
});



app.get("/getProfileData", (req, res) => {
    const userId = req.cookies.user_id;

    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const query = "SELECT name, major, gpa, year, campaign_line, personal_story, experience, organizations, photos, instagram, linkedin, facebook, github, snapchat, tiktok FROM ContestEntries WHERE user_id = $1";

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (!results.rows || results.rows.length === 0) {
            return res.status(404).json({ message: "Student not found." });
        }

        const student = results.rows[0];

        // Parse photos array


        try {
            // Handle photos in the same way as the searchStudents endpoint
            if (student.photos) {
                // Handle both string and array formats
                if (typeof student.photos === "string") {
                    photosArray = JSON.parse(student.photos);
                } else if (Array.isArray(student.photos)) {
                    photosArray = student.photos;
                }

                // Filter out empty entries
                photosArray = photosArray.filter(photo => photo);

                // Set main photo to the first photo if available
                if (photosArray.length > 0) {
                    mainPhoto = photosArray[0];
                }
            }
        } catch (error) {
            console.error("Error parsing photos:", error);
            photosArray = [];
        }

        // Return the complete student data with properly formatted photos
        res.json({
            name: student.name,
            major: student.major,
            gpa: student.gpa,
            year: student.year,
            campaign_line: student.campaign_line,
            personal_story: student.personal_story,
            experience: student.experience,
            organizations: student.organizations,
            // Use the exact same photo format that works in the searchStudents endpoint
            photo: mainPhoto,
            photos: photosArray,
            instagram: student.instagram,
            linkedin: student.linkedin,
            facebook: student.facebook,
            github: student.github,
            snapchat: student.snapchat || null,
            tiktok: student.tiktok || null
        });
    });
});
app.post("/vote", (req, res) => {
    // 1. Check that the user is logged in
    const userId = req.cookies.user_id;
    if (!userId) {
        return res.status(401).json({ message: "Unauthorized: no user_id cookie." });
    }

    // 2. Get the candidateId from the request body
    const { candidateId } = req.body;
    if (!candidateId) {
        return res.status(400).json({ message: "Missing candidateId in request body." });
    }

    // 3. Make sure the user is not voting for themselves
    if (parseInt(candidateId, 10) === parseInt(userId, 10)) {
        return res.status(400).json({ message: "You cannot vote for yourself." });
    }

    // 4. Check if the *voter* has already voted
    const checkVoterQuery = `
        SELECT phase1_vote_done
        FROM ContestEntries
        WHERE user_id = $1
    `;
    db.query(checkVoterQuery, [userId], (err, voterResults) => {
        if (err) {
            console.error("Database error (checkVoterQuery):", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (voterResults.rows.length > 0) {
            const hasVoted = voterResults.rows[0].phase1_vote_done;
            if (hasVoted === true) {
                return res.status(400).json({ message: "You have already voted in phase 1." });
            }
        }

        // 5. Check if the candidate exists in the ContestEntries table
        const checkCandidateQuery = `
            SELECT entry_id, votes
            FROM ContestEntries
            WHERE user_id = $1
        `;
        db.query(checkCandidateQuery, [candidateId], (err, candidateResults) => {
            if (err) {
                console.error("Database error (checkCandidateQuery):", err);
                return res.status(500).json({ message: "Database error." });
            }
            if (candidateResults.rows.length === 0) {
                return res.status(404).json({ message: "Candidate not found." });
            }

            // 6. Increment the 'votes' column for that candidate
            const currentVotes = candidateResults.rows[0].votes || 0;
            const newVotes = currentVotes + 1;

            const updateVotesQuery = `
                UPDATE ContestEntries
                SET votes = $1
                WHERE user_id = $2
            `;
            db.query(updateVotesQuery, [newVotes, candidateId], (err, updateVotesRes) => {
                if (err) {
                    console.error("Database error (updateVotesQuery):", err);
                    return res.status(500).json({ message: "Database error incrementing votes." });
                }

                // 7. Mark the voter as having voted
                if (voterResults.rows.length > 0) {
                    const updateVoterQuery = `
                        UPDATE ContestEntries
                        SET phase1_vote_done = true
                        WHERE user_id = $1
                    `;
                    db.query(updateVoterQuery, [userId], (err, updateVoterRes) => {
                        if (err) {
                            console.error("Database error (updateVoterQuery):", err);
                            return res.status(500).json({ message: "Database error marking user as voted." });
                        }
                        return res.status(200).json({ message: "Vote cast successfully!" });
                    });
                } else {
                    return res.status(200).json({ message: "Vote cast successfully!" });
                }
            });
        });
    });
});

app.get("/studentDetails", (req, res) => {
    const userId = req.query.userId;
    if (!userId) {
        return res.status(400).json({ message: "User ID not provided." });
    }

    const detailsQuery = `
        SELECT * FROM Students
        WHERE userId = ?
    `;

    db.query(detailsQuery, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "Student details not found." });
        }

        res.json(results[0]); // Assuming userId is unique, return the first (and only) result
    });
});

app.get("/getTop20Leaderboard", (req, res) => {
    const query = "SELECT entry_id, name, photos, votes, user_id FROM contestentries ORDER BY votes DESC LIMIT 20";

    db.query(query, (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (!Array.isArray(results.rows)) {
            console.error("Unexpected results format:", results);
            return res.status(500).json({ message: "Unexpected database response." });
        }

        const leaderboard = results.rows.map(entry => {
            let photoUrl = "https://via.placeholder.com/80"; // 默认头像
            try {

                let photoArray = typeof entry.photos === "string" ? JSON.parse(entry.photos) : entry.photos;
                photoUrl = Array.isArray(photoArray) && photoArray.length > 0 ? photoArray[0] : photoUrl;
            } catch (error) {
                console.error("Error parsing photos:", error);
            }

            return {
                id: entry.entry_id,
                name: entry.name,
                photo: photoUrl,
                votes: entry.votes,
                user_id: entry.user_id,
            };
        });

        res.json(leaderboard);
    });


});
app.get("/getLeaderboard", (req, res) => {
    const query = "SELECT entry_id, name, photos, votes, user_id FROM contestentries ORDER BY votes DESC LIMIT 10";

    db.query(query, (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (!Array.isArray(results.rows)) {
            console.error("Unexpected results format:", results);
            return res.status(500).json({ message: "Unexpected database response." });
        }

        const leaderboard = results.rows.map(entry => {
            let photoUrl = "https://via.placeholder.com/80"; // 默认头像
            try {

                let photoArray = typeof entry.photos === "string" ? JSON.parse(entry.photos) : entry.photos;
                photoUrl = Array.isArray(photoArray) && photoArray.length > 0 ? photoArray[0] : photoUrl;
            } catch (error) {
                console.error("Error parsing photos:", error);
            }

            return {
                id: entry.entry_id,
                name: entry.name,
                photo: photoUrl,
                votes: entry.votes,
                user_id: entry.user_id,
            };
        });

        res.json(leaderboard);
    });
});
app.post("/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: "Email is required." });
        }

        // Check if the email exists in your database
        const userQuery = "SELECT user_id, full_name FROM Users WHERE email = $1";
        const userResult = await db.query(userQuery, [email]);

        if (userResult.rows.length === 0) {
            // For security reasons, still return success even if email doesn't exist
            // This prevents email enumeration attacks
            return res.status(200).json({
                message: "If your email is registered, you will receive a password reset link shortly."
            });
        }

        const user = userResult.rows[0];
        const userId = user.user_id;
        const userName = user.name;

        // Generate a secure random token
        const resetToken = crypto.randomBytes(32).toString('hex');

        // Token expires in 1 hour
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1);

        // Delete any existing tokens for this user
        await db.query("DELETE FROM password_reset_tokens WHERE user_id = $1", [userId]);

        // Store the new token in the database
        await db.query(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
            [userId, resetToken, expiresAt]
        );

        // Create the reset link
        const resetLink = `https://www.misscal.net/reset-password.html?token=${resetToken}`;

        // Send the email with the reset link
        const mailOptions = {
            from: '"Miss Cal" <noreply@misscal.net>',
            to: email,
            subject: "Password Reset for Miss Cal",
            text: `Hello ${userName},\n\nYou have requested to reset your password for Miss Cal. Please click the link below to reset your password. This link will expire in 1 hour.\n\n${resetLink}\n\nIf you did not request a password reset, please ignore this email.\n\nBest regards,\nMiss Cal Team`,
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>Hello ${userName},</p>
          <p>You have requested to reset your password for Miss Cal. Please click the button below to reset your password. This link will expire in 1 hour.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" style="background-color: #4CAF50; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
          </div>
          <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
          <p>${resetLink}</p>
          <p>If you did not request a password reset, please ignore this email.</p>
          <p>Best regards,<br>Miss Cal Team</p>
        </div>
      `
        };

        await transporter.sendMail(mailOptions);

        return res.status(200).json({
            message: "If your email is registered, you will receive a password reset link shortly."
        });
    } catch (error) {
        console.error("Forgot password error:", error);
        return res.status(500).json({ message: "An error occurred. Please try again later." });
    }
});

// Endpoint to verify token and reset password
app.post("/reset-password", async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ message: "Token and new password are required." });
        }

        // Verify password complexity
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                message: "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number."
            });
        }

        // Find the token in the database
        const tokenQuery = `
            SELECT t.token_id, t.user_id, t.expires_at, t.used
            FROM password_reset_tokens t
            WHERE t.token = $1
        `;
        const tokenResult = await db.query(tokenQuery, [token]);

        if (tokenResult.rows.length === 0) {
            return res.status(400).json({ message: "Invalid or expired token." });
        }

        const tokenData = tokenResult.rows[0];

        // Check if token is expired
        if (new Date() > new Date(tokenData.expires_at)) {
            return res.status(400).json({ message: "This reset link has expired. Please request a new one." });
        }

        // Check if token has already been used
        if (tokenData.used) {
            return res.status(400).json({ message: "This reset link has already been used." });
        }

        // Hash the new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update the user's password
        await db.query(
            "UPDATE Users SET password = $1 WHERE user_id = $2",
            [hashedPassword, tokenData.user_id]
        );

        // Mark the token as used
        await db.query(
            "UPDATE password_reset_tokens SET used = TRUE WHERE token_id = $1",
            [tokenData.token_id]
        );

        return res.status(200).json({ message: "Password has been successfully reset." });
    } catch (error) {
        console.error("Reset password error:", error);
        return res.status(500).json({ message: "An error occurred. Please try again later." });
    }
});
app.post("/vote-by-email", async (req, res) => {
    try {
        const { email, candidateId } = req.body;

        if (!email || !candidateId) {
            return res.status(400).json({ message: "Email and candidate selection are required." });
        }

        // Verify it's a Berkeley email
        if (!email.endsWith("@berkeley.edu")) {
            return res.status(400).json({ message: "Please use your UC Berkeley email address." });
        }

        // Check if this email has already voted
        const existingVoterQuery = "SELECT * FROM Users WHERE email = $1";
        const existingVoterResult = await db.query(existingVoterQuery, [email]);

        if (existingVoterResult.rows.length > 0) {
            const userId = existingVoterResult.rows[0].user_id;

            // Check if they already voted
            const voterEntryQuery = "SELECT phase1_vote_done FROM ContestEntries WHERE user_id = $1";
            const voterEntryResult = await db.query(voterEntryQuery, [userId]);

            if (voterEntryResult.rows.length > 0 && voterEntryResult.rows[0].phase1_vote_done) {
                return res.status(400).json({ message: "You have already voted." });
            }
        }

        // Generate a voting token
        const voteToken = crypto.randomBytes(32).toString('hex');

        // Store vote intent (either create a user or just store the token)
        let userId;
        if (existingVoterResult.rows.length > 0) {
            // User exists, just use their ID
            userId = existingVoterResult.rows[0].user_id;
        } else {
            // Create a new user with a temporary status
            const tempPassword = crypto.randomBytes(16).toString('hex');
            const hashedPassword = await bcrypt.hash(tempPassword, 10);

            const insertUserQuery = `
        INSERT INTO Users (email, is_verified, password, full_name)
        VALUES ($1, false, $2, $3)
        RETURNING user_id
      `;
            // Use the part before @ as the temporary name
            const tempName = email.split('@')[0];
            const newUserResult = await db.query(insertUserQuery, [email, hashedPassword, tempName]);
            userId = newUserResult.rows[0].user_id;

            // Create empty contest entry to track their vote
            const createEntryQuery = `
        INSERT INTO ContestEntries (user_id, name, form_submitted)
        VALUES ($1, $2, false)
      `;
            await db.query(createEntryQuery, [userId, tempName]);
        }

        // Create voting token table if it doesn't exist
        await db.query(`
      CREATE TABLE IF NOT EXISTS vote_tokens (
        token_id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES Users(user_id),
        token VARCHAR(100) NOT NULL,
        candidate_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT FALSE
      )
    `);

        // Store the voting token
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24); // 24-hour expiration

        const storeTokenQuery = `
      INSERT INTO vote_tokens (user_id, token, candidate_id, expires_at)
      VALUES ($1, $2, $3, $4)
    `;
        await db.query(storeTokenQuery, [userId, voteToken, candidateId, expiresAt]);

        // Send verification email
        const voteLink = `https://www.misscal.net/verify-vote?token=${voteToken}`;

        const mailOptions = {
            from: '"Miss Cal" <mikejamesma23248@gmail.com>',
            to: email,
            subject: "Verify Your Vote for Miss Cal",
            text: `Thank you for voting in the Miss Cal pageant! Please click the link below to verify your vote:\n\n${voteLink}\n\nThis link will expire in 24 hours.\n\nIf you did not attempt to vote, please ignore this email.\n\nBest regards,\nMiss Cal Team`,
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Verify Your Vote</h2>
          <p>Thank you for voting in the Miss Cal pageant!</p>
          <p>Please click the button below to verify your vote. This link will expire in 24 hours.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${voteLink}" style="background-color: #003262; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">Verify My Vote</a>
          </div>
          <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
          <p>${voteLink}</p>
          <p>If you did not attempt to vote, please ignore this email.</p>
          <p>Best regards,<br>Miss Cal Team</p>
        </div>
      `
        };

        await transporter.sendMail(mailOptions);

        return res.status(200).json({
            message: "Please check your email to verify your vote."
        });

    } catch (error) {
        console.error("Vote by email error:", error);
        return res.status(500).json({ message: "An error occurred. Please try again later." });
    }
});

// 2. Create endpoint to verify and process votes
app.get("/verify-vote", async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).json({ message: "Invalid verification link." });
        }

        // Find the token in the database
        const tokenQuery = `
      SELECT vt.*, u.email 
      FROM vote_tokens vt
      JOIN Users u ON vt.user_id = u.user_id
      WHERE vt.token = $1 AND vt.used = false AND vt.expires_at > NOW()
    `;
        const tokenResult = await db.query(tokenQuery, [token]);

        if (tokenResult.rows.length === 0) {
            return res.status(400).json({ message: "Invalid or expired verification link." });
        }

        const voteData = tokenResult.rows[0];

        // Process the vote
        // 1. Increment candidate's vote count
        const updateCandidateQuery = `
      UPDATE ContestEntries
      SET votes = COALESCE(votes, 0) + 1
      WHERE user_id = $1
    `;
        await db.query(updateCandidateQuery, [voteData.candidate_id]);

        // 2. Mark this user as having voted
        const updateVoterQuery = `
      UPDATE ContestEntries
      SET phase1_vote_done = true
      WHERE user_id = $1
    `;
        await db.query(updateVoterQuery, [voteData.user_id]);

        // 3. Mark the token as used
        const updateTokenQuery = `
      UPDATE vote_tokens
      SET used = true
      WHERE token = $1
    `;
        await db.query(updateTokenQuery, [token]);

        // 4. Set the user as verified
        const verifyUserQuery = `
      UPDATE Users
      SET is_verified = true
      WHERE user_id = $1
    `;
        await db.query(verifyUserQuery, [voteData.user_id]);

        // Return a success page
        res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Vote Confirmed - Miss Cal</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 40px;
            background: linear-gradient(to bottom right, #FDB515, #FDB515);
            color: #333;
            text-align: center;
          }
          .container {
            max-width: 600px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
          }
          h1 {
            color: #003262;
          }
          .btn {
            display: inline-block;
            background: #003262;
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            margin-top: 20px;
          }
          .create-account {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Vote Confirmed!</h1>
          <p>Thank you for participating in the Miss Cal pageant voting.</p>
          <p>Your vote has been successfully counted.</p>
          
          <div class="create-account">
            <h2>Want to join the pageant?</h2>
            <p>You already have an account created with your email. You can now set a password and participate in the Miss Cal pageant!</p>
            <a href="https://www.misscal.net/create-password?email=${encodeURIComponent(voteData.email)}" class="btn">Create Password</a>
          </div>
        </div>
      </body>
      </html>
    `);

    } catch (error) {
        console.error("Vote verification error:", error);
        res.status(500).send("An error occurred. Please try again later.");
    }
});

// 3. Add endpoint for users to set a password and "upgrade" to a full account
app.post("/create-password", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: "Email and password are required." });
        }

        // Verify password complexity
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                message: "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number."
            });
        }

        // Find the user
        const userQuery = "SELECT * FROM Users WHERE email = $1";
        const userResult = await db.query(userQuery, [email]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "User not found." });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update the user's account
        const updateUserQuery = `
      UPDATE Users
      SET password = $1
      WHERE email = $2
    `;
        await db.query(updateUserQuery, [hashedPassword, email]);

        return res.status(200).json({
            message: "Password created successfully! You can now log in with your email and password."
        });

    } catch (error) {
        console.error("Create password error:", error);
        return res.status(500).json({ message: "An error occurred. Please try again later." });
    }
});



app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});


