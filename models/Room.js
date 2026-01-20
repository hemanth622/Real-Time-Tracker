const mongoose = require('mongoose');

const roomSchema = new mongoose.Schema(
  {
    roomId: { type: String, required: true, unique: true, index: true },
    name: { type: String, required: true, trim: true },
    description: { type: String, default: '', trim: true },
    ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    inviteToken: { type: String, index: true, unique: true, sparse: true },
    bannedUserIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    chatMuted: { type: Boolean, default: false },
    locationRequestsDisabled: { type: Boolean, default: false },
    locationHistoryEnabled: { type: Boolean, default: false },
  },
  { timestamps: { createdAt: true, updatedAt: true } }
);

module.exports = mongoose.model('Room', roomSchema);

