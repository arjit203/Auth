const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserVerificationSchema = new Schema({
  userId: { type: String },
 uniqueString: { type: String, unique: true },
  createdAt: { type: Date },
  expiresAt: { type: Date },
});

const UserVerification = mongoose.model('UserVerification', UserVerificationSchema);

module.exports = UserVerification;
