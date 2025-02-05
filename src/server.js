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
const cookieParser = require('cookie-parser');
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(cookieParser());

// Middleware
app.use(bodyParser.json());
app.use(cors()); // Enable CORS
// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
    dest: 'uploads/', // Temporary storage folder
    limits: { files: 10 } // Limit to a maximum of 10 files
});


// MySQL Database Connection
const db = mysql.createConnection({
    host: "127.0.0.1",
    user: "root",
    password: "Mzy20020212",
    database: "accountForStudent",
});

db.connect((err) => {
    if (err) {
        console.error("Database connection error:", err);
        process.exit(1);
    }
    console.log("Connected to MySQL database.");
});
app.post("/submitForm", upload.array("photos", 10), (req, res) => {
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
        linkedin,
        facebook,
        github,
        snapchat,
        tiktok,
    } = req.body;

    const photos = req.files.map((file) => file.path);

    if (!user_id) {
        return res.status(400).json({ message: "User ID is required." });
    }

    // Check if the user already exists in the database
    const queryCheck = "SELECT * FROM ContestEntries WHERE user_id = ?";
    db.query(queryCheck, [user_id], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
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
                return res.status(200).json({ message: "No changes detected. Nothing to update." });
            }

            // Construct the dynamic update query
            const setClause = Object.keys(fieldsToUpdate)
                .map((key) => `${key} = ${fieldsToUpdate[key]}`)
                .join(", ");

            const queryUpdate = `UPDATE ContestEntries SET ${setClause} WHERE user_id = ?`;
            valuesToUpdate.push(user_id); // Add user_id to the end of the query values

            db.query(queryUpdate, valuesToUpdate, (err, results) => {
                if (err) {
                    console.error("Database error:", err);
                    return res.status(500).json({ message: "Database error." });
                }
                res.status(200).json({ message: "Contest entry updated successfully!" });
            });
        } else {
            // User does not exist, insert new data
            const queryInsert = `
                INSERT INTO ContestEntries (
                    user_id, major, gpa, name, campaign_line, personal_story, experience, organizations,
                    instagram, linkedin, facebook, github, snapchat, tiktok, photos
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ],
                (err, results) => {
                    if (err) {
                        console.error("Database error:", err);
                        return res.status(500).json({ message: "Database error." });
                    }
                    res.status(201).json({ message: "Contest entry created successfully!" });
                }
            );
        }
    });
});
// Signup Endpoint
const { sendVerificationEmail } = require("./sendVerificationEmail");
const { generateVerificationToken } = require("./generateVerificationToken");


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
    const queryCheckEmail = "SELECT email FROM Users WHERE email = ?";
    db.query(queryCheckEmail, [email], async (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.length > 0) {
            return res.status(409).json({ message: "Email already exists." });
        }

        // 2) Generate token & hashed password (in memory)
        const verificationToken = generateVerificationToken();
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password, 10);
        } catch (hashErr) {
            console.error("Error hashing password:", hashErr);
            return res.status(500).json({ message: "Internal server error." });
        }

        // 3) Attempt to send the email *before* inserting user into DB
        try {
            await sendVerificationEmail(email, verificationToken);
        } catch (mailErr) {
            console.error("Error sending verification email:", mailErr);
            // If we fail here, we do *not* insert the user
            return res.status(500).json({ message: "Failed to send verification email." });
        }

        // 4) If email sent successfully, now insert user with is_verified=0
        const queryInsert = `
      INSERT INTO Users (full_name, email, password, email_verification_token, is_verified)
      VALUES (?, ?, ?, ?, 0)
    `;
        db.query(queryInsert, [full_name, email, hashedPassword, verificationToken], (err, insertResults) => {
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
      SET is_verified = 1, email_verification_token = NULL
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
    // If you store user_id in a cookie:
    res.clearCookie("user_id");
    // If you use sessions, you might do: req.session.destroy(...)

    res.json({ message: "Logged out successfully" });
});
// Login Endpoint
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required." });
    }

    const query = "SELECT * FROM Users WHERE email = ?";
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "Email not found." });
        }

        const user = results[0];

        try {
            const isPasswordCorrect = await bcrypt.compare(password, user.password);
            if (!isPasswordCorrect) {
                return res.status(401).json({ message: "Incorrect password." });
            }

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

    const query = "SELECT * FROM ContestEntries WHERE user_id = ?";
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }
        if (results.length === 0) {
            console.log("No profile found for user_id:", userId);
            return res.status(404).json({ message: "Profile not found." });
        }
        results.photos = JSON.parse(results.photos || "[]").map(photo => `http://localhost:3000/${photo}`);
        console.log("Profile data retrieved:", results[0]);
        res.json(results[0]);
    });
});


app.post("/updateProfile", upload.none(), (req, res) => {
    const userId = req.cookies.user_id;
    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    // Extract fields from the request body
    const {
        name,  // Add name field
        major,
        gpa,
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
    } = req.body;

    // Map fields to their values
    const fieldsToUpdate = {
        name,  // Add name to the fields to update
        major,
        gpa,
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
    };

    // Convert 'None' to empty string for URL fields (if present)
    for (const field in fieldsToUpdate) {
        if (fieldsToUpdate[field] === 'None') {
            fieldsToUpdate[field] = '';  // Make sure 'None' is treated as an empty string
        }
    }

    // Filter out undefined or empty fields
    const validFields = Object.entries(fieldsToUpdate).filter(([key, value]) => value !== undefined && value !== "");

    // If no fields are valid, return an error
    if (validFields.length === 0) {
        return res.status(400).json({ message: "No fields to update." });
    }

    // Construct the dynamic query
    const setClause = validFields.map(([key]) => `${key} = ?`).join(", ");
    const queryParams = validFields.map(([_, value]) => value);
    queryParams.push(userId); // Add userId to the end for the WHERE clause

    const queryUpdate = `UPDATE ContestEntries SET ${setClause} WHERE user_id = ?`;

    // Execute the query
    db.query(queryUpdate, queryParams, (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }
        res.json({ message: "Profile updated successfully!" });
    });
});

app.get("/getStudentDetails", (req, res) => {
    const userId = req.cookies.user_id;

    if (!userId) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    const query = "SELECT name, major, gpa, campaign_line, personal_story, experience, organizations, photos, instagram, linkedin, facebook, github, tiktok FROM ContestEntries WHERE user_id = ?";
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
        WHERE name LIKE ? OR major LIKE ?
    `;

    db.query(sqlQuery, [`%${query}%`, `%${query}%`], (err, results) => {
        if (err) {
            console.error("Database error:", err);
            return res.status(500).json({ message: "Database error." });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: "No students found." });
        }

        const students = results.map(student => ({
            userId: student.user_id,
            name: student.name,
            major: student.major,
            gpa: student.gpa,
            personal_story: student.personal_story,
            campaign_line: student.campaign_line,
            experience: student.experience,
            organizations: student.organizations,
            photo: (student.photos && JSON.parse(student.photos)[0]) || "default-photo.jpg"// Use the first photo or a default placeholder
        }));

        res.json(students);
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

    // 4. Check if the *voter* has already voted (optional)
    const checkVoterQuery = `
        SELECT phase1_vote_done 
        FROM ContestEntries 
        WHERE user_id = ?
    `;
    db.query(checkVoterQuery, [userId], (err, voterResults) => {
        if (err) {
            console.error("Database error (checkVoterQuery):", err);
            return res.status(500).json({ message: "Database error." });
        }

        // If the user hasn’t even created an entry, you can decide what to do.
        // This check is optional; maybe you allow voters who didn't create an entry themselves.
        if (voterResults.length === 0) {
            // For example, disallow voting if the voter has no entry:
            // return res.status(400).json({ message: "You haven't registered to vote." });

            // Or ignore if you don't care whether they have an entry themselves
        } else {
            // If phase1_vote_done == 1, they've already voted
            if (voterResults[0].phase1_vote_done === 1) {
                return res.status(400).json({ message: "You have already voted in phase 1." });
            }
        }

        // 5. Check if the candidate exists in the ContestEntries table
        const checkCandidateQuery = `
            SELECT entry_id, votes 
            FROM ContestEntries 
            WHERE user_id = ?
        `;
        db.query(checkCandidateQuery, [candidateId], (err, candidateResults) => {
            if (err) {
                console.error("Database error (checkCandidateQuery):", err);
                return res.status(500).json({ message: "Database error." });
            }
            if (candidateResults.length === 0) {
                return res.status(404).json({ message: "Candidate not found." });
            }

            // 6. Increment the 'votes' column for that candidate
            const currentVotes = candidateResults[0].votes || 0;
            const newVotes = currentVotes + 1;

            const updateVotesQuery = `
                UPDATE ContestEntries
                SET votes = ?
                WHERE user_id = ?
            `;
            db.query(updateVotesQuery, [newVotes, candidateId], (err, updateVotesRes) => {
                if (err) {
                    console.error("Database error (updateVotesQuery):", err);
                    return res.status(500).json({ message: "Database error incrementing votes." });
                }

                // 7. Mark the voter as having voted (optional)
                //    Only do this if they already exist in ContestEntries
                if (voterResults.length > 0) {
                    const updateVoterQuery = `
                        UPDATE ContestEntries
                        SET phase1_vote_done = 1
                        WHERE user_id = ?
                    `;
                    db.query(updateVoterQuery, [userId], (err, updateVoterRes) => {
                        if (err) {
                            console.error("Database error (updateVoterQuery):", err);
                            return res
                                .status(500)
                                .json({ message: "Database error marking user as voted." });
                        }
                        return res.status(200).json({ message: "Vote cast successfully!" });
                    });
                } else {
                    // If the voter isn't in the table, you might just say "Vote cast"
                    // (or handle differently). For example:
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




app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

