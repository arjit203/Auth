const express = require('express');
const Userrouter = express.Router();

const User = require('./../models/user');  //mongodb user model

const UserVerification = require('./../models/UserVerification');//mongodb userverification model
const PasswordReset = require('./../models/PasswordReset');

//email handler
const nodemailer = require('nodemailer');

// password handler
const bcrypt = require('bcrypt');


//unique string
// const {v4 : uuidv4} = require("uuid");

require('dotenv').config();

// //nodemailer transporter 
// let transporter = nodemailer.createTransport({
//     service: "gmail",
//     auth: {
//         user: process.env.AUTH_EMAIL,
//         pass: process.env.AUTH_PASS,
//     },
//     logger: true,
//     debug: true,
// });


// //Successful Testing
// transporter.verify((error,success) =>
// {
//     if(error){
//         console.log(error);
//     }
//     else{
//         console.log("Ready for messages");
//         console.log(success);
//     }
// });



//SIGNUP

Userrouter.post('/signup', async (req, res) => {
    let { name, email, password } = req.body;

    if ((name && typeof name === 'string') && (email && typeof email === 'string') && (password && typeof password === 'string')) {
        name = name.trim();
        email = email.trim();
        password = password.trim();
    }

    console.log("Received name:", name);

    if (name == "" || email == "" || password == "") {
        return res.status(404).json({
            status: "FAILED",
            message: "Empty input fields!"
        });
    } else if (!/^[a-zA-Z\s]*$/.test(name)) {
        return res.status(404).json({
            status: "FAILED",
            message: "Invalid name entered"
        });
    } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
        return res.status(404).json({
            status: "FAILED",
            message: "Invalid email entered"
        });
    } else if (password.length < 8) {
        return res.status(404).json({
            status: "FAILED",
            message: "Password is too short!"
        });
    }

    // Checking if user already exists
    try {
        User.findOne({ email })
            .then(isUserExist => {
                if (isUserExist) {
                    return res.status(404).json({
                        status: "FAILED",
                        message: "User with the provided email already exists"
                    });
                } else {
                    // Hash the password
                    const saltRounds = 10;
                    bcrypt.hash(password, saltRounds).then(hashedPassword => {
                        // Create a new user
                        const newUser = new User({
                            name,
                            email,
                            password: hashedPassword,
                            verified: false
                        });

                        newUser.save()
                            .then(result => {
                                // Handle account verification
                                console.log("User saved successfully:", result);
                                sendVerificationEmail(result, res);
                            })
                            .catch(err => {
                                console.error("Error saving user:", err);
                                return res.status(500).json({
                                    status: "FAILED",
                                    message: "An error occurred while saving the user Account!!."
                                });
                            });
                    })
                        .catch(err => {
                            console.log(err);
                            return res.status(500).json({
                                status: "FAILED",
                                message: "An error Occured while hashing password!"
                            });
                        });
                }
            })
            .catch(err => {
                console.log(err);
                return res.status(500).json({
                    status: "FAILED",
                    message: "An error Occured while checking for existing user!"
                });
            });
    } catch (err) {
        console.log(err);
        return res.status(500).json({
            status: "FAILED",
            message: "An unexpected error occurred!"
        });
    }
});

  
        

//send verification email
const sendVerificationEmail = ({_id,email},res) =>
{
    //url to be used in the email
    const currentUrl = "http://localhost:5600/";
    const uniqueString = uuidv4() + _id;
    console.log("ddd",process.env.AUTH_EMAIL)
    const mailOptions ={
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Verify Your Email",
        html :
       ` <p>Verify your email address.</p>
        <p>This link <b>expires in 1 hour</b>.</p>
        <p>Press <a href="${currentUrl}user/verify/${_id}/${uniqueString}">here</a> to proceed.</p>`
    };

    //hash the uniqueString
    const saltRounds= 10;
    bcrypt.hash(uniqueString, saltRounds).then((hashedUniqueString) =>{
        const newVerification = new UserVerification({
            userId: _id,
            uniqueString: hashedUniqueString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000, // 1 hour
        });

        newVerification.save()
            .then(() => {
                console.log("verification email sent successfully")
                transporter.sendMail(mailOptions)
                    .then(() => {
                        res.json({
                            status: "PENDING",
                            message: "Verification email sent!",
                        });
                    })
                    .catch((error) => {
                        console.log("Error while sending")
                        return res.status(500).json({
                            status: "FAILED",
                            message: "Failed to send verification email!",
                        });
                    });
            })
            .catch((error) => {
                console.log("Error while saving");
                return res.status(500).json({
                    status: "FAILED",
                    message: "An error occurred while saving the verification record!",
                });
            });
    })
        .catch((error) =>
    {   console.log("Error while hashing");
        return res.status(500).json({
            status: "FAILED",
            message : "Error occured while hashing email data!",
        });
    }
    )

}

//verify email
// Userrouter.get('/verify/:userId/:uniqueString', (req, res) => {
//     const { userId, uniqueString } = req.params;

//     UserVerification.findOne({ userId })
//         .then((record) => {
//             if (!record) {
//                 return res.status(404).json({ status: 'FAILED', message: 'Verification link expired or invalid.' });
//             } else {
//                 bcrypt.compare(uniqueString, record.uniqueString).then((isMatch) => {
//                     if (isMatch) {
//                         User.updateOne({ _id: userId }, { verified: true })
//                             .then(() => {
//                                 UserVerification.deleteOne({ userId })
//                                     .then(() => res.redirect('/login'))
//                                     .catch((err) =>  res.status(500).json({ status: 'FAILED', message: 'Error updating user.' }));
//                             })
//                             .catch((err) =>  res.status(500).json({ status: 'FAILED', message: 'Error updating user.' }));
//                     } else {
//                         return res.status(401).json({ status: 'FAILED', message: 'Invalid verification link.' });
//                     }
//                 });
//             }
//         })
//         .catch((err) => res.status(500).json({ status: 'FAILED', message: 'Error verifying user.' }));

// });


//Signin
Userrouter.post('/login', async(req,res) =>
{
    let{email, password,} = req.body;
    email = email.trim();    //Extra spaces entered by the user (before or after their input) are removed.
    password = password.trim();

    if(email === "" || password === ""){
        return res.status(404).json({
    status : "FAILED",
    message : "Empty credentials supplied"
});
}
try{
    //check if user exists
   const user = await User.findOne({email});
   if (!user) {
    return res.json({ 
        status: "FAILED",
        message: "Invalid credentials!"
     });
}
          
            //check if user is verified
            if(!user.verified){
                return res.status(404).json ({
                    status : "FAILED",
                    message : "Email hasn't been verified yet. Check your inbox",
                });
            }

                const isPasswordMatch = await bcrypt.compare(password,user.password);
                if (!isPasswordMatch) {
                    return res.json({
                        status: "FAILED",
                        message: "Invalid password!"
                    });
                } 


                return res.json({
                    status: "SUCCESS",
                    message: "Sign-in successful!",
                    data: user,
                });
             } 
             catch (error) {
                console.error(error);
                return res.json({
                    status: "FAILED",
                    message: "An error occurred during Sign-in.",
                });
            }
});

     

//Password reset stuff
Userrouter.post("/requestPasswordReset",(req,res) =>
{
    const {email} = req.body;

    //check if email exists
    if (!email || email.trim() === "") {
        return res.json({
            status: "FAILED",
            message: "Email is required!"
        });
    }

    User.findOne({ email }).then(user => {
        if (!user) {
            return res.json({
                status: "FAILED",
                message: "No user found with this email!"
            });
        }
    })
    .catch(error =>{
        console.log(error);
        res.json({
            status : "FAILED",
            message : "An error occured while checking for existing user",
        })
    })
});


//send password reset email
// const sendResetEmail = ({_id, email}, redirectUrl, res ) =>{
//      const resetString = uuidv4 + _id;
//      //First, we clear all existing reset records
//      PasswordReset.deleteMany({ userId : _id})
//      .then(result => {
//         //reset records deleted successfully 
//         //Now we send the email

//         //mail options
//         const mailOptions ={
//             from: process.env.AUTH_EMAIL,
//             to: email,
//             subject: "Password reset",
//             html :
//            ` <p>Use the link below to reset your password.</p>
//             <p>This link <b>expires in 1 hour</b>.</p>
//             <p>Press <a href="${redirectUrl} + "/" + ${_id} + "/" + ${resetString}">here</a> to proceed.</p>`
//         };
       
//         //hash the reset string
//          const saltRounds = 10;
//          bcrypt.hash().then(hashedResetString =>{
//             //set values in password reset collection
//             const newPasswordReset = new PasswordReset({
//                   userId : _id,
//                   uniqueString: hashedResetString,
//                   createdAt: Date.now(),
//                   expiresAt: Date.now() + 3600000
//             });
//            newPasswordReset.save()
//            .then(() => {
//              transporter.sendMail(mailOptions)
//              .then(() => {
//                 //reset email sent and password
//                 res.json({
//                     status : "PENDING",
//                     message : "Password reset email sent",
//                 })
//              })
//              .catch(error => {
//                 console.log(error);
//                 return res.status(500).json({
//                     status : "FAILED",
//                     message : "Password reset email failed!",
//                 });
//              })

//            })
//            .catch(error => {
//             console.log(error);
//             return res.status(500).json({
//                 status : "FAILED",
//                 message : "Couldn't save password reset data!",
//             });
//            })
//          }).catch(error => {
//             console.log(error);
//             return res.status(500).json({
//                 status : "FAILED",
//                 message : "An error occured while hashing the password reset data!",
//             });

//          })

//      })
//      .catch(error => {
//         console.log(error);
//         res.json({
//             status : "FAILED",
//             message : "Clearing existing password reset records failed",
//         });
//      })
// }


module.exports = Userrouter