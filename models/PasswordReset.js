const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PasswordResetSchema = new Schema({
  userId: { type: String },
 uniqueString: { type: String, unique: true },
  createdAt: { type: Date },
  expiresAt: { type: Date },
});

const PasswordReset = mongoose.model('PasswordReset', PasswordResetSchema);

module.exports = PasswordReset;
