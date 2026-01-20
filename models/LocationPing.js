const mongoose = require('mongoose');

const locationPingSchema = new mongoose.Schema(
  {
    roomId: { type: String, required: true, index: true },
    userId: { type: String, required: true, index: true }, // app uses string ids in sockets; keep consistent
    latitude: { type: Number, required: true },
    longitude: { type: Number, required: true },
    accuracy: { type: Number, default: null },
    timestamp: { type: Date, required: true, index: true },
  },
  { timestamps: false }
);

locationPingSchema.index({ roomId: 1, userId: 1, timestamp: -1 });

module.exports = mongoose.model('LocationPing', locationPingSchema);

