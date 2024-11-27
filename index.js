//mongodb

const connectDB = require("./config/database")
const express = require('express');
const app = express();
const path = require('path');
const port = 5001;
const Userrouter = require('./api/user1');

//For acceppting post form data
const bodyParser = require('express').json;
app.use(bodyParser());

app.use('/user',Userrouter);

// app.use(express.static(path.join(__dirname, 'public')));



connectDB();
app.listen(port,() =>
{
    console.log(`Server running on port ${port}`);
})
// console.log(process.env.AUTH_EMAIL,process.env.AUTH_PASS);