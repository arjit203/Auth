//mongodb

const connectDB = require("./config/database")  //database connection
const express = require('express');
const session = require('express-session');
const app = express();
const path = require('path');
const port = 5500;
const cors = require('cors'); // Import CORS
const Userrouter = require('./api/user1');

//For acceppting post form data
const bodyParser = require('express').json;
app.use(bodyParser());

app.use(session({
    secret: 'ace-gik', // Replace with a random secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true } // Set secure: true if using HTTPS
  }));


  app.use(cors({
    origin: '*', // Allow all origins
}));


// Your routes here
app.get('/api', (req, res) => {
    res.json({ message: 'CORS-enabled response' });
});


app.use(express.urlencoded({ extended : false}))

app.use('/user',Userrouter);

//Default route for health check or debugging
app.get('/', (req, res) => {
    res.send('Authentication Server is Running');
});

connectDB();
app.listen(port||process.env.port,() =>
{
    console.log(`Server is running on port ${port}`);
})


// Error handling middleware for unexpected errors
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        status: "FAILED",
        message: "An internal server error occurred"
    });
});
// console.log(process.env.AUTH_EMAIL,process.env.AUTH_PASS);