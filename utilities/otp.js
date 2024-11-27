exports.generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString(); // to generate a 6-digit OTP
};
