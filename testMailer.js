import { sendVerificationEmail } from './mailer.js';

(async () => {
    const userEmail = 'recipient-email@gmail.com'; // Replace with the recipient's email
    const verificationLink = 'http://localhost:3000/verify-email?token=test-token';
    await sendVerificationEmail(userEmail, verificationLink);
})();