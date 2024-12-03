const express = require("express");
const Userrouter = express.Router();

const User = require("./../models/user"); //mongodb user model
const UserVerification = require("../models/UserVerification"); //mongodb userverification model
const PasswordReset = require("./../models/PasswordReset");

//email handler
const nodemailer = require("nodemailer");

// password handler
const bcrypt = require("bcrypt");

require("dotenv").config();

//SIGNUP

Userrouter.post("/signup", async (req, res) => {
  let { name, email, password } = req.body;

  // Validate input fields
  if (
    name &&
    typeof name === "string" &&
    email &&
    typeof email === "string" &&
    password &&
    typeof password === "string"
  ) {
    name = name.trim();
    email = email.trim();
    password = password.trim();
  }

  if (name == "" || email == "" || password == "") {
    return res.status(404).json({
      status: "FAILED",
      message: "Empty input fields!",
    });
  } else if (!/^[a-zA-Z\s]*$/.test(name)) {
    return res.status(404).json({
      status: "FAILED",
      message: "Invalid name entered",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    return res.status(404).json({
      status: "FAILED",
      message: "Invalid email entered",
    });
  } else if (password.length < 8) {
    return res.status(404).json({
      status: "FAILED",
      message: "Password is too short!",
    });
  }

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      if (!existingUser.verified) {
        // Resend verification email if the user is not verified
        await UserVerification.deleteMany({ userId: existingUser._id }); // Remove old verification records
       
        sendVerificationEmail(existingUser, res); // Resend verification email
       
        return;
      }
      return res.status(404).json({
        status: "FAILED",
        message: "User with the provided email already exists",
      });
    }

    // Hash the password
    const saltRounds = 10;
    bcrypt
      .hash(password, saltRounds)
      .then(async (hashedPassword) => {
        // Create a new user
        const newUser = new User({
          name,
          email,
          password: hashedPassword,
          verified: false,
        });

        // Save the user
        await newUser.save();

        // Send verification email
        sendVerificationEmail(newUser, res); // Send verification email after user is saved
      })
      .catch((err) => {
        return res.status(500).json({
          status: "FAILED",
          message: "An error occurred while hashing the password.",
        });
      });
  } catch (err) {
    return res.status(500).json({
      status: "FAILED",
      message: "An error occurred while checking for existing user.",
    });
  }
});

//unique string
const { v4: uuidv4 } = require("uuid");

//send verification email
const sendVerificationEmail = ({ _id, email, name }, res) => {
  // Validate if email exists
  if (!email || email.trim() === "") {
    console.error("No email provided!");
    return res.status(400).json({
      status: "FAILED",
      message: "No email provided!",
    });
  }

  // Check if the email is from a Gmail domain
  if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(email)) {
    console.log("Invalid email domain:", email);
    return res.status(400).json({
      status: "FAILED",
      message: "Only Gmail addresses are allowed for verification.",
    });
  }

  // Create a transport for sending email
  let transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.AUTH_EMAIL,
      pass: process.env.AUTH_PASS,
    },
    logger: true,
    debug: true,
  });

  const uniqueString = uuidv4() + _id; // Create a unique string for the verification link

  // Use the BASE_URL from environment variable to generate the link
  const verificationLink = `${process.env.BASE_URL}/user/verify-email/${_id}/${uniqueString}`;

  // Log the verification link for debugging
  console.log("Verification Link:", verificationLink);

  const mailOptions = {
    from: process.env.AUTH_EMAIL, // Sender's email
    to: email, // Recipient's email
    subject: "Verify Your Email Address",
    html: `
            <p>Hi ${name},</p>
            <p>Thank you for signing up.</p>
            <p>Please verify your email by clicking the link below:</p>
            <p><a href="${verificationLink}">Verify Email</a></p>
            <p>This link <b>expires in 1 hour</b>.</p>
        `,
  };

  console.log("Sending verification email to:", email); // Log email for debugging

  // Hash the unique string and save it for verification
  bcrypt
    .hash(uniqueString, 10)
    .then((hashedUniqueString) => {
      const newVerification = new UserVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 3600000, // 1 hour expiry time
      });

      newVerification
        .save()
        .then(() => {
          // Send the verification email
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.log("Error sending email:", error);
              return res.status(500).json({
                status: "FAILED",
                message: "Failed to send verification email.",
              });
            } else {
              console.log("Email sent:", info.response);
              res.json({
                status: "SUCCESS",
                message: "Verification email sent!",
              });
            }
          });
        })
        .catch((error) => {
          console.log("Error saving verification record:", error);
          return res.status(500).json({
            status: "FAILED",
            message: "An error occurred while saving verification record.",
          });
        });
    })
    .catch((error) => {
      console.log("Error hashing verification string:", error);
      return res.status(500).json({
        status: "FAILED",
        message: "Error occurred while hashing verification string.",
      });
    });
};

//verify email
Userrouter.get("/verify-email/:userId/:uniqueString", async (req, res) => {
  const { userId, uniqueString } = req.params;

  try {
    // Find the verification record by userId
    const record = await UserVerification.findOne({ userId });

    if (!record) {
      return res.status(404).json({
        status: "FAILED",
        message: "Verification link expired or invalid.",
      });
    }

    const now = Date.now();

    // Check if the verification link has expired
    if (now > record.expiresAt) {
      await UserVerification.deleteOne({ userId }); // Delete expired record
      return res.status(404).json({
        status: "FAILED",
        message: "Verification link has expired.",
      });
    }

    // Compare the uniqueString in the URL with the hashed string stored in the DB
    const isMatch = await bcrypt.compare(uniqueString, record.uniqueString);

    if (isMatch) {
      // If matched, update the user to verified
      await User.findByIdAndUpdate(userId, { verified: true }, { new: true });

      // Delete old records when a new verification email is sent:
      await UserVerification.deleteOne({ userId });

      //  // For browser requests (clicking link):
      if (req.headers.accept?.includes("text/html")) {
        // Respond with an HTML redirect for browsers
        return res.redirect("/login");
      } else {
        // Respond with JSON for API clients or non-browser requests
        return res.status(200).json({
          status: "SUCCESS",
          message: "Email verified successfully! Please log in.",
        });
      }
    } else {
      return res.status(401).json({
        status: "FAILED",
        message: "Invalid verification link.",
      });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      status: "FAILED",
      message: "Error verifying user.",
    });
  }
});

//LOGIN
Userrouter.post("/login", async (req, res) => {
  let { email, password } = req.body;
  email = email.trim(); //Extra spaces entered by the user (before or after their input) are removed.
  password = password.trim();

  if (email === "" || password === "") {
    return res.status(400).json({
      status: "FAILED",
      message: "Empty credentials supplied",
    });
  }
  try {
    //check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        status: "FAILED",
        message: "Invalid E-mail!",
      });
    }

    //check if user is verified
    if (!user.verified) {
      return res.status(403).json({
        status: "FAILED",
        message: "Email hasn't been verified yet. Check your inbox",
      });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(403).json({
        status: "FAILED",
        message: "Invalid password!",
      });
    }

    return res.status(200).json({
      status: "SUCCESS",
      message: "Log-in successful!",
      data: user,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      status: "FAILED",
      message: "An error occurred during Sign-in.",
    });
  }
});

// Initialize nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

// Request Forgot password
Userrouter.post("/forgotPassword", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      status: "FAILED",
      message: "Email is required.",
    });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        status: "FAILED",
        message: "No account with the supplied email exists!",
      });
    }

    if (!user.verified) {
      return res.status(400).json({
        status: "FAILED",
        message: "Email hasn't been verified yet. Check your inbox.",
      });
    }

    const resetString = uuidv4() + user._id;

    // Clear any existing reset records
    await PasswordReset.deleteMany({ userId: user._id });

    // Hash reset string
    const hashedResetString = await bcrypt.hash(resetString, 10);

    const newPasswordReset = new PasswordReset({
      userId: user._id,
      uniqueString: hashedResetString,
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000, // 1 hour
    });

    await newPasswordReset.save();

    const resetUrl = `${process.env.BASE_URL}/user/resetPassword/${user._id}/${resetString}`;

    const mailOptions = {
      from: process.env.AUTH_EMAIL,
      to: email,
      subject: "Password Reset",
      html: `<p>Someone has requested a link to change your password.</p>
      <br>
      <p>Click the link below to reset your password.</p>
             <a href="${resetUrl}">Change my Password</a>
             <br>
              <p>This link <b>expires in 1 hour</b></p>
              <p>If you didn't request this, please ignore this email.</p>
              <p>Your password won't change until you access the link and create a new one.</p>
             `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error(error);
        return res.status(500).json({
          status: "FAILED",
          message: "Failed to send password reset email.",
        });
      }
      res.status(200).json({
        status: "PENDING",
        message: "Password reset email sent successfully.",
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: "FAILED",
      message: "An error occurred while processing the request.",
    });
  }
});

Userrouter.post("/resetPasswordSubmit/:userId/:resetString", async (req, res) => {
  const { userId, resetString } = req.params;
  const { newPassword, confirmPassword } = req.body;

  if (!newPassword || !confirmPassword) {
    return res.status(400).json({
      status: "FAILED",
      message: "New password and confirmation password are required.",
    });
  }

   // Check if the new password meets the minimum length requirement
   if (newPassword.length < 8) {
    return res.status(400).json({
      status: "FAILED",
      message: "Password must be at least 8 characters long.",
    });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({
      status: "FAILED",
      message: "Passwords do not match.",
    });
  }

  try {
    // Check if the reset link exists
    const resetRecord = await PasswordReset.findOne({ userId });

    if (!resetRecord) {
      return res.status(404).json({
        status: "FAILED",
        message: "Invalid or expired reset link.",
      });
    }

    // Check if the reset link has expired
    if (Date.now() > resetRecord.expiresAt) {
      await PasswordReset.deleteOne({ userId }).catch((error) => {
        console.error(error);
        return res.status(500).json({
          status: "FAILED",
          message: "An error occurred while deleting expired reset record.",
        });
      });

      return res.status(400).json({
        status: "FAILED",
        message: "Reset link has expired.",
      });
    }

    // Compare reset string
    const isMatch = await bcrypt
      .compare(resetString, resetRecord.uniqueString)
      .catch((error) => {
        console.error(error);
        return res.status(500).json({
          status: "FAILED",
          message: "An error occurred while comparing the reset string.",
        });
      });

    if (!isMatch) {
      return res.status(400).json({
        status: "FAILED",
        message: "Invalid reset link.",
      });
    }


     // Find the user to check if the old password is the same as the new password
     const user = await User.findById(userId);

     // Compare the new password with the user's current password
     const isOldPasswordSame = await bcrypt.compare(newPassword, user.password);
     if (isOldPasswordSame) {
       return res.status(400).json({
         status: "FAILED",
         message: "New password cannot be the same as the old password.",
       });
      } 



    // Hash the new password and update it
    const hashedPassword = await bcrypt.hash(newPassword, 10).catch((error) => {
      console.error(error);
      return res.status(500).json({
        status: "FAILED",
        message: "An error occurred while hashing the new password.",
      });
    });

    await User.findByIdAndUpdate({ _id: userId }, { password: hashedPassword } , { new: true } ).catch(
      (error) => {
        console.error(error);
        return res.status(500).json({
          status: "FAILED",
          message: "An error occurred while updating the password.",
        });
      }
    );

    // Delete the password reset record after successful password change
    await PasswordReset.deleteOne({ userId }).catch((error) => {
      console.error(error);
      return res.status(500).json({
        status: "FAILED",
        message: "An error occurred while deleting the password reset record.",
      });
    });

    res.status(200).json({
      status: "SUCCESS",
      message: "Password reset successfully.You can now log in.",
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      status: "FAILED",
      message: "An error occurred while resetting the password.",
    });
  }
});

Userrouter.get("/resetPassword/:userId/:uniqueString", async (req, res) => {
  const { userId, uniqueString } = req.params;

  try {
    // Find the reset password record
    const record = await PasswordReset.findOne({ userId });

    if (!record) {
      return res.status(404).json({
        status: "FAILED",
        message: "Invalid or expired reset link.",
      });
    }

    // Check if the reset link has expired
    const now = Date.now();
    if (now > record.expiresAt) {
      return res.status(404).json({
        status: "FAILED",
        message: "Reset link has expired.",
      });
    }

    // Verify the unique string
    const isMatch = await bcrypt.compare(uniqueString, record.uniqueString);
    if (!isMatch) {
      return res.status(401).json({
        status: "FAILED",
        message: "Invalid reset link.",
      });
    }

      // Redirect to the POST route for password reset
      return res.redirect(307, `/user/resetPasswordSubmit/${userId}/${uniqueString}`);
    } catch (error) {
      console.error(error);
      return res.status(500).json({
        status: "FAILED",
        message: "Server error while verifying reset link.",
      });
    }
  });


//LOGOUT
Userrouter.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({
          status: 'FAILED',
          message: 'Error during session destruction!',
        });
      }
      res.status(200).json({
        status: 'SUCCESS',
        message: 'Logged out successfully!',
      });
    });
  } else {
    return res.status(400).json({
      status: 'FAILED',
      message: 'No active session found.',
    });
  }
});



module.exports = Userrouter;
