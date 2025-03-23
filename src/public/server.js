const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

const multer = require('multer'); // Used for handling file uploads
const fs = require('fs');

const app = express(); // Initialize 'app'
const PORT = process.env.PORT || 3000;
app.use(cors({
    origin: ["https://misscal.net", "https://www.misscal.net"],  // ✅ Allow your front-end origins
    credentials: true,  // ✅ Required for cookies and authentication
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],  // ✅ Allow these methods
    allowedHeaders: ["Content-Type", "Authorization"],  // ✅ Allow necessary headers
}));
const cookieParser = require('cookie-parser');
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(cookieParser());
app.use((req, res, next) => {
    if (!req.cookies.user_id && req.path !== "/login" && req.path !== "/signup") {
        return res.status(401).json({ message: "Unauthorized: Please log in." });
    }
    next();
});

app.use("/photos", express.static(path.join(__dirname, "uploads")));
// Middleware
app.use(bodyParser.json());
app.use((req, res, next) => {
    if (req.method === "OPTIONS") {
        return res.sendStatus(200);
    }

    if (!req.cookies.user_id && req.path !== "/login" && req.path !== "/signup") {
        return res.status(401).json({ message: "Unauthorized: Please log in." });
    }
    next();
});







// ❌ Remove this duplicate CORS setup in the error handler (causing conflicts)
// app.use((err, req, res, next) => {
//     res.header("Access-Control-Allow-Origin", "https://misscal.net");
//     res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
//     res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
//     res.header("Access-Control-Allow-Credentials", "true");
//     next(err);
// });

// ✅ Handle preflight OPTIONS request properly



// Now define routes
app.get('/test', (req, res) => {
    res.json({ message: 'CORS working!' });
});
// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
    dest: 'uploads/', // Temporary storage folder
    limits: { files: 10 } // Limit to a maximum of 10 files
});



const { Pool } = require("pg");
require("dotenv").config(); // Load environment variables

// MySQL Database Connection
/*const db = mysql.createConnection({
    //host: "127.0.0.1",
    host: "ep-little-cell-a6siaqa3-pooler.us-west-2.aws.neon.tech",
    //user: "root",
    user: "neondb_owner",
    //password: "Mzy20020212",
    password: "npg_N3jhmKgHalk6",
    //database: "accountForStudent",
    database: "neondb",

    connectionString: process.env.DATABASE_URL, // Use .env variable
    ssl: {
        rejectUnauthorized: false, // Required for Neon SSL connections
    },

});

db.connect((err) => {
    if (err) {
        console.error("Database connection error:", err);
        process.exit(1);
    }
    console.log("Connected to MySQL database.");
});
*/
const db = new Pool({
    connectionString: "postgresql://neondb_owner:npg_N3jhmKgHalk6@ep-little-cell-a6siaqa3-pooler.us-west-2.aws.neon.tech/neondb?sslmode=require", // Using the Neon Database URL
    ssl: {
        rejectUnauthorized: false, // Required for Neon
    },
});

db.connect()
    .then(() => console.log("✅ Connected to Neon PostgreSQL database."))
    .catch((err) => {
        console.error("❌ Database connection error:", err);
        process.exit(1);
    });

module.exports = db;
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

    const query = "SELECT name, major, gpa, campaign_line, personal_story, experience, organizations, photos, instagram, linkedin, facebook, github, tiktok FROM ContestEntries WHERE user_id = $1";

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (!results.rows || results.rows.length === 0) {
            return res.status(404).json({ message: "Student not found." });
        }

        const student = results.rows[0];

        // Handle Photos Safely
        let photo = "";
        try {
            const photosArray = JSON.parse(student.photos || "[]");
            photo = photosArray.length > 0 ? photosArray[0] : "";
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

        const students = results.rows.map(student => ({
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
            photo: (student.photos && Array.isArray(student.photos) && student.photos.length > 0)
                ? student.photos[0]  // Use the first image
                : "default-photo.jpg" // Use a placeholder if no photo exists
        }));

        res.json(students);
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






app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});


