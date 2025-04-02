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
const rateLimit = require("express-rate-limit");
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });
const helmet = require('helmet');
require("dotenv").config(); // Load environment variables


// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: "Too many login attempts, please try again later"
});

// Set up basic middleware in correct order
app.set('trust proxy', 1);
app.use(cookieParser());
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
    }
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json());

// CORS setup
app.use(cors({
    origin: ["https://misscal.net", "https://www.misscal.net"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "CSRF-Token"],
}));

// Define public paths that don't need authentication
const PUBLIC_PATHS = [
    "/login",
    "/signup",
    "/forgot-password",
    "/reset-password",
    "/verify-email",
    "/vote-by-email",
    "/verify-vote",
    "/searchStudents",
    "/create-password",
    "/getTop20Leaderboard"
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
        user: process.env.GMAIL_USER,
        // For Gmail, you'll need to create an App Password in your Google Account
        pass: process.env.GMAIL_PASS// Replace with your app password


    }
});

// Database setup

const db = new Pool({
    connectionString: process.env.DATABASE_URL,
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
    limits: { files: 10, fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (!file.mimetype.match(/^image\/(jpeg|png|gif)$/)) {
            return cb(new Error('Only image files are allowed'), false);
        }
        cb(null, true);
    }
});
app.post("/submitForm", csrfProtection, upload.array("photos", 10), (req, res) => {
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

    // Verify it's the right email format
    if (!email.endsWith("@berkeley.edu")) {
        return res.status(400).json({ message: "Email must be a UC Berkeley email." });
    }

    try {
        // Check if email exists in the main Users table
        const userResults = await db.query("SELECT user_id, is_verified, needs_password, phase1_vote_done FROM Users WHERE email = $1", [email]);

        if (userResults.rows.length > 0) {
            const user = userResults.rows[0];

            // If the user account exists but was created through email voting (needs_password=true)
            if (user.needs_password) {
                // Update the existing account instead of creating a new one
                const hashedPassword = await bcrypt.hash(password, 10);

                await db.query(
                    `UPDATE Users 
                     SET full_name = $1, password = $2, is_verified = true, needs_password = false
                     WHERE user_id = $3`,
                    [full_name, hashedPassword, user.user_id]
                );

                return res.status(200).json({
                    message: "Account setup complete! You can now log in with your email and password.",
                    votingStatus: user.phase1_vote_done ? "Your vote has already been counted." : "You can now vote for your favorite contestant!"
                });
            } else {
                // Regular account already exists
                return res.status(409).json({ message: "Email already exists. Please log in." });
            }
        }

        // Generate token and hash password
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const hashedPassword = await bcrypt.hash(password, 10);

        // Set expiration (24 hours from now)
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);

        // Check if email exists in PendingVerifications
        const pendingResults = await db.query(
            "SELECT id FROM PendingVerifications WHERE email = $1",
            [email]
        );

        if (pendingResults.rows.length > 0) {
            // Email exists in pending verifications, update the existing record
            await db.query(
                `UPDATE PendingVerifications
                 SET full_name = $1, password = $2, verification_token = $3,
                     expires_at = $4, created_at = CURRENT_TIMESTAMP
                 WHERE email = $5`,
                [full_name, hashedPassword, verificationToken, expiresAt, email]
            );
        } else {
            // New pending verification
            await db.query(
                `INSERT INTO PendingVerifications
                     (full_name, email, password, verification_token, expires_at)
                 VALUES ($1, $2, $3, $4, $5)`,
                [full_name, email, hashedPassword, verificationToken, expiresAt]
            );
        }

        // Send verification email
        const verificationLink = `https://server1.misscal.net/verify-email?token=${verificationToken}`;

        const mailOptions = {
            from: '"Miss Cal" <mikejamesma23248@gmail.com>',
            to: email,
            subject: "Verify Your Email for Miss Cal",
            text: `Hello ${full_name},\n\nThank you for signing up for Miss Cal! Please verify your email by clicking the link below:\n\n${verificationLink}\n\nThis link will expire in 24 hours.\n\nBest regards,\nMiss Cal Team`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Verify Your Email</h2>
                    <p>Hello ${full_name},</p>
                    <p>Thank you for signing up for Miss Cal! Please verify your email by clicking the button below:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationLink}" style="background-color: #003262; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">Verify My Email</a>
                    </div>
                    <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
                    <p>${verificationLink}</p>
                    <p>Best regards,<br>Miss Cal Team</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);

        res.status(201).json({
            message: "Signup successful! Please check your email to verify your account."
        });

    } catch (error) {
        console.error("Error in signup process:", error);
        return res.status(500).json({
            message: "An error occurred during signup. Please try again."
        });
    }
});


app.post("/logout", (req, res) => {
    res.clearCookie("user_id", { path: "/" }); // ✅ Remove the user_id cookie
    res.status(200).json({ message: "Logged out successfully!" });
});
// Login Endpoint
app.post("/login", loginLimiter, (req, res) => {
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

            // Check if email is verified
            if (!user.is_verified) {
                return res.status(403).json({
                    message: "Please verify your email before logging in. Check your inbox for a verification link."
                });
            }

            // Continue with login (set cookie, etc)
            res.cookie("user_id", user.user_id, {
                httpOnly: true,
                secure: true,
                sameSite: "None",
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days,
                path: "/",
            });

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
            // Initialize with default photo



            // Handle JSONB 'photos' field, which is the primary photo field



            // Ensure URL is properly formatted

            let photoUrl = `https://server1.misscal.net/${student.photos}`;

            // For debug logging
            console.log(`Photo for ${student.name}:`, {
                originalPhotos: student.photos,
                processedPhotoUrl: photoUrl
            });

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
            votes: student.votes,
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

    // 4. Check if the *voter* has already voted - CHECK IN USERS TABLE INSTEAD
    const checkVoterQuery = `
        SELECT phase1_vote_done
        FROM Users
        WHERE user_id = $1
    `;

    db.query(checkVoterQuery, [userId], (err, voterResults) => {
        if (err) {
            console.error("Database error (checkVoterQuery):", err);
            return res.status(500).json({ message: "Database error." });
        }

        // If the user exists and has already voted
        if (voterResults.rows.length > 0 && voterResults.rows[0].phase1_vote_done === true) {
            return res.status(400).json({ message: "You have already voted in phase 1." });
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

                // 7. Mark the voter as having voted IN THE USERS TABLE
                const updateVoterQuery = `
                    UPDATE Users
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
            /*try {

                let photoArray = typeof entry.photos === "string" ? JSON.parse(entry.photos) : entry.photos;
                photoUrl = Array.isArray(photoArray) && photoArray.length > 0 ? photoArray[0] : photoUrl;
            } catch (error) {
                console.error("Error parsing photos:", error);
            }*/
            if (entry.photos) {
                photoUrl = `https://server1.misscal.net/${entry.photos}`;
            } else {
                photoUrl = "https://via.placeholder.com/80";
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
            /*try {

                let photoArray = typeof entry.photos === "string" ? JSON.parse(entry.photos) : entry.photos;
                photoUrl = Array.isArray(photoArray) && photoArray.length > 0 ? photoArray[0] : photoUrl;
            } catch (error) {
                console.error("Error parsing photos:", error);
            }*/
            if (entry.photos) {
                photoUrl = `https://server1.misscal.net/${entry.photos}`;
            } else {
                photoUrl = "https://via.placeholder.com/80";
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
        const userQuery = "SELECT user_id, phase1_vote_done FROM Users WHERE email = $1";
        const userResult = await db.query(userQuery, [email]);

        if (userResult.rows.length > 0) {
            // User exists
            const user = userResult.rows[0];

            if (user.phase1_vote_done) {
                return res.status(400).json({ message: "This email has already been used to vote." });
            }

            // Generate a voting verification token
            const voteToken = crypto.randomBytes(32).toString('hex');

            // Update the user with the new verification token and candidate choice
            await db.query(
                "UPDATE Users SET email_verification_token = $1, temp_candidate_id = $2 WHERE user_id = $3",
                [voteToken, candidateId, user.user_id]
            );
        } else {
            // User doesn't exist, create a temporary account
            const voteToken = crypto.randomBytes(32).toString('hex');
            const tempPassword = crypto.randomBytes(16).toString('hex');
            const hashedPassword = await bcrypt.hash(tempPassword, 10);

            // Extract name from email (part before @)
            const emailParts = email.split('@');
            const tempName = emailParts[0];

            // Create new unverified user with vote intent
            await db.query(
                `INSERT INTO Users (email, password, full_name, is_verified, phase1_vote_done,
                                    email_verification_token, temp_candidate_id, needs_password)
                 VALUES ($1, $2, $3, false, false, $4, $5, true)`,
                [email, hashedPassword, tempName, voteToken, candidateId]
            );
        }

        // Get the token (whether from existing or new user)
        const tokenQuery = "SELECT email_verification_token FROM Users WHERE email = $1";
        const tokenResult = await db.query(tokenQuery, [email]);
        const voteToken = tokenResult.rows[0].email_verification_token;

        // Send verification email
        const voteLink = `https://server1.misscal.net/verify-vote?token=${voteToken}`;

        const mailOptions = {
            from: '"Miss Cal" <mikejamesma23248@gmail.com>',
            to: email,
            subject: "Verify Your Vote for Miss Cal",
            text: `Thank you for voting in the Miss Cal pageant! Please click the link below to verify your vote:\n\n${voteLink}\n\nThis link will expire in 24 hours.\n\nIf you did not attempt to vote, please ignore this email.\n\nBest regards,\nMiss Cal Team`,
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Verify Your Vote</h2>
          <p>Thank you for voting in the Miss Cal pageant!</p>
          <p>Please click the button below to verify your vote:</p>
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
            message: "Please check your email or Spam to verify your vote. "
        });

    } catch (error) {
        console.error("Vote by email error:", error);
        return res.status(500).json({ message: "An error occurred. Please try again later." });
    }
});

app.get("/verify-vote", async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).send("Missing verification token.");
        }

        // Find the user with this token
        const userQuery = `
            SELECT * FROM Users
            WHERE email_verification_token = $1 AND phase1_vote_done = false
        `;
        const userResult = await db.query(userQuery, [token]);

        if (userResult.rows.length === 0) {
            return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Invalid Token - Miss Cal</title>
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
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Invalid or Expired Token</h1>
            <p>The verification link is invalid or has expired.</p>
            <a href="https://www.misscal.net/" class="btn">Return to Home</a>
          </div>
        </body>
        </html>
      `);
        }

        const user = userResult.rows[0];
        const candidateId = user.temp_candidate_id;

        // Increment candidate's vote count
        const updateCandidateQuery = `
            UPDATE ContestEntries
            SET votes = COALESCE(votes, 0) + 1
            WHERE user_id = $1
        `;
        await db.query(updateCandidateQuery, [candidateId]);

        // Mark this user as having voted and clear the token
        const updateUserQuery = `
            UPDATE Users
            SET phase1_vote_done = true,
                email_verification_token = NULL
            WHERE user_id = $1
        `;
        await db.query(updateUserQuery, [user.user_id]);

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
          .success-icon {
            font-size: 64px;
            color: #28a745;
            margin-bottom: 20px;
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
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
      </head>
      <body>
        <div class="container">
          <div class="success-icon">
            <i class="fas fa-check-circle"></i>
          </div>
          <h1>Vote Confirmed!</h1>
          <p>Thank you for participating in the Miss Cal pageant voting.</p>
          <p>Your vote has been successfully counted.</p>
          
          <a href="https://www.misscal.net/" class="btn">Return to Home</a>
          
          ${user.needs_password ? `
          <div class="create-account">
            <h2>Want to join the pageant?</h2>
            <p>You already have an account created with your email. You can now set a password and participate in the Miss Cal pageant!</p>
            <a href="https://www.misscal.net/signup.html" class="btn">Create Password</a>
          </div>
          ` : ''}
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
// GET endpoint to serve the create-password form
app.get("/create-password", (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).send("Email parameter is missing.");
    }

    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Create Password - Miss Cal</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
      <style>
        :root {
          --berkeley-blue: #003262;
          --california-gold: #FDB515;
          --accent-pink: #ff6f61;
        }
        
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          margin: 0;
          padding: 0;
          background: linear-gradient(to bottom right, #FDB515, #FDB515);
          color: #333;
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        
        .container {
          width: 90%;
          max-width: 500px;
          background: white;
          padding: 30px;
          border-radius: 10px;
          box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }
        
        h1 {
          color: var(--berkeley-blue);
          text-align: center;
          margin-bottom: 25px;
        }
        
        .form-group {
          margin-bottom: 20px;
        }
        
        .form-group label {
          display: block;
          margin-bottom: 8px;
          font-weight: bold;
        }
        
        .form-control {
          width: 100%;
          padding: 12px 15px;
          border: 2px solid #ddd;
          border-radius: 8px;
          font-size: 1rem;
          transition: all 0.3s;
        }
        
        .form-control:focus {
          border-color: var(--berkeley-blue);
          outline: none;
          box-shadow: 0 0 0 3px rgba(0, 50, 98, 0.2);
        }
        
        .password-container {
          position: relative;
        }
        
        .toggle-password {
          position: absolute;
          right: 15px;
          top: 50%;
          transform: translateY(-50%);
          cursor: pointer;
          color: #666;
        }
        
        .password-requirements {
          font-size: 0.9rem;
          color: #666;
          margin-top: 8px;
        }
        
        .btn {
          display: block;
          width: 100%;
          padding: 12px 0;
          background: var(--berkeley-blue);
          color: white;
          border: none;
          border-radius: 30px;
          font-size: 1rem;
          font-weight: bold;
          cursor: pointer;
          transition: all 0.3s;
          text-align: center;
        }
        
        .btn:hover {
          background: var(--california-gold);
          color: var(--berkeley-blue);
          transform: translateY(-3px);
          box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .alert {
          padding: 15px;
          border-radius: 8px;
          margin-bottom: 20px;
          display: none;
        }
        
        .alert-success {
          background-color: #d4edda;
          color: #155724;
          border: 1px solid #c3e6cb;
        }
        
        .alert-danger {
          background-color: #f8d7da;
          color: #721c24;
          border: 1px solid #f5c6cb;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Create Your Password</h1>
        <div id="alertBox" class="alert"></div>
        
        <form id="createPasswordForm">
          <input type="hidden" id="emailInput" name="email" value="${email}">
          
          <div class="form-group">
            <label for="passwordInput">New Password</label>
            <div class="password-container">
              <input type="password" id="passwordInput" name="password" class="form-control" required>
              <i class="toggle-password fas fa-eye"></i>
            </div>
            <div class="password-requirements">
              Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, and one number.
            </div>
          </div>
          
          <div class="form-group">
            <label for="confirmPasswordInput">Confirm Password</label>
            <div class="password-container">
              <input type="password" id="confirmPasswordInput" class="form-control" required>
              <i class="toggle-password fas fa-eye"></i>
            </div>
          </div>
          
          <button type="submit" class="btn">Create Password</button>
        </form>
      </div>
      
      <script>
        document.addEventListener('DOMContentLoaded', function() {
          const form = document.getElementById('createPasswordForm');
          const alertBox = document.getElementById('alertBox');
          const passwordInput = document.getElementById('passwordInput');
          const confirmPasswordInput = document.getElementById('confirmPasswordInput');
          const togglePasswordButtons = document.querySelectorAll('.toggle-password');
          
          // Toggle password visibility
          togglePasswordButtons.forEach(button => {
            button.addEventListener('click', function() {
              const input = this.previousElementSibling;
              if (input.type === 'password') {
                input.type = 'text';
                this.classList.remove('fa-eye');
                this.classList.add('fa-eye-slash');
              } else {
                input.type = 'password';
                this.classList.remove('fa-eye-slash');
                this.classList.add('fa-eye');
              }
            });
          });
          
          // Form submission
          form.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            // Clear previous alerts
            alertBox.style.display = 'none';
            alertBox.textContent = '';
            alertBox.className = 'alert';
            
            // Get values
            const email = document.getElementById('emailInput').value;
            const password = passwordInput.value;
            const confirmPassword = confirmPasswordInput.value;
            
            // Validate password match
            if (password !== confirmPassword) {
              showAlert('Passwords do not match.', 'danger');
              return;
            }
            
            // Validate password requirements
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]{8,}$/;
            if (!passwordRegex.test(password)) {
              showAlert('Password does not meet the requirements.', 'danger');
              return;
            }
            
            try {
              // Submit the form data
              const response = await fetch('server1.misscal.net/create-password', {
                method: 'POST',
                credentials: "include",
                headers: {
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
              });
              
              const data = await response.json();
              
              if (response.ok) {
                showAlert(data.message, 'success');
                // Redirect to login page after 2 seconds
                setTimeout(() => {
                  window.location.href = '/sign-in.html';
                }, 2000);
              } else {
                showAlert(data.message || 'An error occurred.', 'danger');
              }
            } catch (error) {
              showAlert('An error occurred. Please try again.', 'danger');
              console.error('Error:', error);
            }
          });
          
          function showAlert(message, type) {
            alertBox.textContent = message;
            alertBox.className = 'alert alert-' + type;
            alertBox.style.display = 'block';
          }
        });
      </script>
    </body>
    </html>
  `);
});
app.get("/verify-email", async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).send("Missing verification token.");
    }

    try {
        // Find the pending verification with this token
        const pendingQuery = "SELECT * FROM PendingVerifications WHERE verification_token = $1 AND expires_at > CURRENT_TIMESTAMP";
        const pendingResult = await db.query(pendingQuery, [token]);

        if (pendingResult.rows.length === 0) {
            return res.status(400).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Invalid Token - Miss Cal</title>
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
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Invalid or Expired Token</h1>
                        <p>The verification link is invalid or has expired.</p>
                        <a href="https://www.misscal.net/signup.html" class="btn">Return to Sign Up</a>
                    </div>
                </body>
                </html>
            `);
        }

        const pendingUser = pendingResult.rows[0];

        // Check if email already exists in Users table (someone else verified with this email)
        const existingUser = await db.query("SELECT user_id FROM Users WHERE email = $1", [pendingUser.email]);

        if (existingUser.rows.length > 0) {
            // Delete the pending verification
            await db.query("DELETE FROM PendingVerifications WHERE id = $1", [pendingUser.id]);

            return res.status(400).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Email Already Verified - Miss Cal</title>
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
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Email Already Verified</h1>
                        <p>This email address has already been verified.</p>
                        <a href="https://www.misscal.net/sign-in.html" class="btn">Sign In</a>
                    </div>
                </body>
                </html>
            `);
        }

        // Create the verified user in the Users table
        await db.query(
            `INSERT INTO Users (full_name, email, password, is_verified) 
             VALUES ($1, $2, $3, true)`,
            [pendingUser.full_name, pendingUser.email, pendingUser.password]
        );

        // Delete the pending verification
        await db.query("DELETE FROM PendingVerifications WHERE id = $1", [pendingUser.id]);

        // Return success page
        res.send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>Email Verified - Miss Cal</title>
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
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Email Verified!</h1>
                    <p>Your email has been successfully verified.</p>
                    <p>You can now log in to your Miss Cal account.</p>
                    <a href="https://www.misscal.net/sign-in.html" class="btn">Sign In</a>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error("Email verification error:", error);
        res.status(500).send("An error occurred. Please try again later.");
    }
});

app.post("/resend-verification", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: "Email is required." });
    }

    try {
        // Check if user is already verified
        const verifiedUser = await db.query("SELECT user_id FROM Users WHERE email = $1", [email]);

        if (verifiedUser.rows.length > 0) {
            return res.status(400).json({
                message: "This email is already verified. Please log in."
            });
        }

        // Get the pending verification
        const pendingQuery = "SELECT * FROM PendingVerifications WHERE email = $1";
        const pendingResult = await db.query(pendingQuery, [email]);

        if (pendingResult.rows.length === 0) {
            return res.status(404).json({
                message: "Email not found. Please sign up first."
            });
        }

        const pendingUser = pendingResult.rows[0];

        // Generate new token and update expiration
        const newToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);

        // Update the pending verification
        await db.query(
            `UPDATE PendingVerifications 
             SET verification_token = $1, expires_at = $2, created_at = CURRENT_TIMESTAMP
             WHERE id = $3`,
            [newToken, expiresAt, pendingUser.id]
        );

        // Send new verification email
        const verificationLink = `https://server1.misscal.net/verify-email?token=${newToken}`;

        const mailOptions = {
            from: '"Miss Cal" <mikejamesma23248@gmail.com>',
            to: email,
            subject: "Verify Your Email for Miss Cal",
            text: `Hello ${pendingUser.full_name},\n\nHere is your new verification link for Miss Cal. Please verify your email by clicking the link below:\n\n${verificationLink}\n\nThis link will expire in 24 hours.\n\nBest regards,\nMiss Cal Team`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Verify Your Email</h2>
                    <p>Hello ${pendingUser.full_name},</p>
                    <p>Here is your new verification link for Miss Cal. Please verify your email by clicking the button below:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationLink}" style="background-color: #003262; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold;">Verify My Email</a>
                    </div>
                    <p>If the button above doesn't work, you can copy and paste the following link into your browser:</p>
                    <p>${verificationLink}</p>
                    <p>Best regards,<br>Miss Cal Team</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({
            message: "Verification email resent successfully! Please check your email."
        });

    } catch (error) {
        console.error("Error resending verification:", error);
        return res.status(500).json({
            message: "An error occurred. Please try again."
        });
    }
});

app.get('/stats', async (req, res) => {
    try {
        // Get participant count from contestentries table
        const participantQuery = await db.query('SELECT COUNT(*) FROM contestentries WHERE form_submitted = true');
        const participantCount = parseInt(participantQuery.rows[0].count);

        // Get total votes count
        const votesQuery = await db.query('SELECT SUM(votes) FROM contestentries');
        const voteCount = parseInt(votesQuery.rows[0].sum) || 0;

        // Calculate days left until deadline
        const now = new Date();
        const deadline = new Date('2025-04-30T23:59:59');
        const daysLeft = Math.ceil((deadline - now) / (1000 * 60 * 60 * 24));

        // Return all statistics
        res.json({
            participantCount,
            voteCount,
            daysLeft
        });
    } catch (error) {
        console.error('Error fetching statistics:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

app.get('/get-csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});
app.get('/getAllContestants', async (req, res) => {
    try {
        // Check if user is authenticated
        if (!req.cookies.user_id) {
            return res.status(401).json({ error: 'You must be logged in to access this resource' });
        }

        // Connect to the database and query all contestants
        const client = await db.connect();
        try {
            // Query the contestants table, selecting only necessary fields for ranking
            const query = `
        SELECT 
          entry_id, 
          name, 
          votes, 
          year,
          major
        FROM 
          contestentries 
        WHERE 
          form_submitted = true
        ORDER BY 
          votes DESC
      `;

            const result = await client.query(query);

            // Return the array of contestants
            res.json(result.rows);
        } finally {
            // Release the client back to the pool
            client.release();
        }
    } catch (error) {
        console.error('Error in getAllContestants:', error);
        res.status(500).json({ error: 'An error occurred while fetching contestants' });
    }
});

// API endpoint to count entries


// API endpoint to count votes


// API endpoint to get user info



app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
});


