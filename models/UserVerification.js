const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// UserVerification schema
const UserVerificationSchema = new Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId, // Refers to User collection
    ref: 'User',
    required: true,
  },
  uniqueString: {
    type: String,
    unique: true,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

const UserVerification = mongoose.model('UserVerification', UserVerificationSchema);

module.exports = UserVerification;
