const nodemailer = require("nodemailer");

// Example direct credentials (but usually you'd store these in environment variables)
const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
        user: "mikejamesma23248@gmail.com",
        pass: "tjttcfaypyrwgrox"
    }
});

async function sendVerificationEmail(email, token) {
    const verificationLink = `http://localhost:3000/verify-email?token=${token}`;

    const mailOptions = {
        from: "mikejamesma23248@gmail.com",
        to: email,
        subject: "Please verify your email",
        html: `
      <h1>Verify Your Email</h1>
      <p>Thanks for signing up! Click the link below to verify your email:</p>
      <a href="${verificationLink}">${verificationLink}</a>
    `
    };

    // Attempt to send. If this throws an error, the caller can catch it and avoid DB insert.
    await transporter.sendMail(mailOptions);
}

module.exports = { sendVerificationEmail };
