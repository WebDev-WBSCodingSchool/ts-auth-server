import { Schema, model } from 'mongoose';

export type UserType = {
  _id: Schema.Types.ObjectId;
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
  roles: string[];
};

const userSchema = new Schema<UserType>(
  {
    firstName: { type: String, required: [true, 'Firstname is required'] },
    lastName: { type: String, required: [true, 'Lastname is required'] },
    email: {
      type: String,
      require: true,
      unique: true
    },
    password: {
      type: String,
      require: true
    },
    roles: {
      type: [String],
      default: ['user']
    }
  },
  {
    timestamps: { createdAt: true, updatedAt: false }
  }
);

const User = model('User', userSchema);

export default User;
