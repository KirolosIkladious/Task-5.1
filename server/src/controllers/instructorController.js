
import bcrypt from 'bcryptjs';
import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// Validate login input
const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(80).required(),
  password: Joi.string().min(1).max(256).required()
}).unknown(false);

// Validate search input
const searchSchema = Joi.object({
  name: Joi.string().trim().min(1).max(100).required()
}).unknown(false);

// Fields that can be shown publicly
const PUBLIC_FIELDS = 'name department role';

// Safe instructor profile for login response
function loginProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// Escape special regex characters in search input
function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    // Step 1: Validate incoming input using Joi
    const { error, value } = loginSchema.validate(
      req.body,
      { convert: false }
    );

    if (error) {
      return res.status(400).json({
        message: 'Invalid username or password format'
      });
    }

    // Step 2: Find instructor using username only
    const instructor = await Instructor.findOne({
      username: value.username
    }).select('+password');

    // Step 3: Compare entered password with bcrypt hash
    if (
      !instructor ||
      !(await bcrypt.compare(value.password, instructor.password))
    ) {
      return res.status(401).json({
        message: 'Invalid credentials'
      });
    }

    // Step 4: Return only safe instructor details
    return res.json({
      instructor: loginProfile(instructor)
    });

  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .lean();

    res.json({ instructors });

  } catch (err) {
    next(err);
  }
}

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // Step 1: Validate search parameters
    const { error, value } = searchSchema.validate(
      req.query,
      { convert: false }
    );

    if (error) {
      return res.status(400).json({
        message: 'Search requires a valid name string'
      });
    }

    // Step 2: Safely search by instructor name
    const instructors = await Instructor.find({
      name: {
        $regex: escapeRegex(value.name),
        $options: 'i'
      }
    })
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .lean();

    // Step 3: Return only public data
    res.json({
      count: instructors.length,
      instructors
    });

  } catch (err) {
    next(err);
  }
}
