//mongodb

const connectDB = require("./config/database")  //database connection
const express = require('express');
const app = express();
const path = require('path');
const port = 3600;
const Userrouter = require('./api/user1');

//For acceppting post form data
const bodyParser = require('express').json;
app.use(bodyParser());

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