require('dotenv').config();
const mongoose = require('mongoose');


const connectDB = async () => {
    try {
        await mongoose.connect(process.env.DB);
        console.log('MongoDB connected successfully');
    } catch (err) {
        console.error('Failed to connect to MongoDB', err);
        process.exit(1);
    }
};

module.exports = connectDB; 