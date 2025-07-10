import { Schema, model } from 'mongoose';
import { REFRESH_TOKEN_TTL } from '#config';

const refreshTokenSchema = new Schema(
  {
    token: { type: String, required: true, unique: true },
    userId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
    jti: { type: String, required: true, unique: true },
    sessionId: { type: String, required: true },
    deviceInfo: String,
    expireAt: {
      type: Date,
      default: new Date(Date.now() + REFRESH_TOKEN_TTL)
    }
  },
  {
    timestamps: { createdAt: true, updatedAt: false }
  }
);

// Creates a TTL (Time-To-Live) Index. Document will be removed automatically after <REFRESH_TOKEN_TTL> seconds.
refreshTokenSchema.index({ expireAt: 1 }, { expireAfterSeconds: 0 });

refreshTokenSchema.index({ userId: 1 });
refreshTokenSchema.index({ jti: 1 });

const RefreshToken = model('RefreshToken', refreshTokenSchema);

export default RefreshToken;
