import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables from .env file

const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10), // Convert to an integer
    secure: process.env.EMAIL_SECURE === 'true', // Convert to a boolean
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

export async function sendVerificationEmail(userEmail, verificationCode) {
    try {
        const mailOptions = { // Email options
            from: `"Bloglet" <${process.env.EMAIL_USER}>`, // Sender address
            to: userEmail, // Recipient address
            subject: "Your Verification Code", // Email subject
            html: ` 
                <p>Thank you for registering!</p>
                <p>Your verification code is:</p>
                <h2>${verificationCode}</h2>
                <p>This code will expire in 30 seconds.</p>
            `, // Include the verification code in the email
        };

        await transporter.sendMail(mailOptions); // Send the email
        console.log("Verification email sent to " + userEmail); // Log success
    } catch (error) {
        console.error("Error sending verification email:", error); // Log errors
    }
}