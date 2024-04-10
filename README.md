# Email password and social login with MFA + bot detection

We customize the login flow here to only ask for otp-email as a second factor during email password sign in (and not even sign up). This is so that users have a good sign up experience, and to specifically protected against credentials stuffing attacks in the email password sign in flow.

