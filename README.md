# Email password and social login with MFA + bot detection

## Flow description
A user can sign up via social or email password login with automatic account linking. During sign in with email password, they are asked to also complete an otp email challenge as a second factor measure.

## Security features
- Preventing against credential stuffing attacks by requiring an otp email challenge during email password sign in. We also determine if this is required based on a risk score.
- Automatic account linking only for verified accounts.
- Bot detection to prevent sign ins / sign ups.
- Customizable password policy
- Brute force detection for OTP login flow
- Breached password detection to prevent sign up with a known password.
- Session security:
    - CSRF protection
    - HttpOnly cookies
    - Rotating refresh tokens
