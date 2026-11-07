
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const instructorSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true
    },

    username: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },

    // Password is hidden by default
    password: {
      type: String,
      required: true,
      select: false
    },

    department: {
      type: String
    },

    role: {
      type: String,
      enum: ['instructor', 'superadmin'],
      default: 'instructor'
    },

    // Sensitive data must not be returned by default
    apiKey: {
      type: String,
      select: false
    },

    privateEmail: {
      type: String,
      select: false
    },

    privatePhone: {
      type: String,
      select: false
    }
  },
  { timestamps: true }
);

// Hash passwords automatically before saving
instructorSchema.pre('save', async function () {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(
      this.password,
      12
    );
  }
});

export const Instructor = mongoose.model(
  'Instructor',
  instructorSchema
);
