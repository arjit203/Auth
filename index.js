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

connectDB();
app.listen(port||process.env.port,() =>
{
    console.log(`Server running on port ${port}`);
})
// console.log(process.env.AUTH_EMAIL,process.env.AUTH_PASS);