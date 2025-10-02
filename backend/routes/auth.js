const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { asyncHandler } = require('../middleware/errorHandler');
const { logSecurityEvent } = require('../middleware/logger');
const { isValidAddress } = require('../utils/blockchain');

const router = express.Router();

// Validation schemas
const registerSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).max(100).required(),
  walletAddress: Joi.string().pattern(/^0x[a-fA-F0-9]{40}$/).optional(),
  firstName: Joi.string().max(50).optional(),
  lastName: Joi.string().max(50).optional(),
  organization: Joi.string().max(100).optional()
});

const loginSchema = Joi.object({
  identifier: Joi.string().required(), // username or email
  password: Joi.string().required(),
  walletAddress: Joi.string().pattern(/^0x[a-fA-F0-9]{40}$/).optional()
});

const updateProfileSchema = Joi.object({
  firstName: Joi.string().max(50).optional(),
  lastName: Joi.string().max(50).optional(),
  organization: Joi.string().max(100).optional(),
  bio: Joi.string().max(500).optional(),
  walletAddress: Joi.string().pattern(/^0x[a-fA-F0-9]{40}$/).optional()
});

const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string().min(8).max(100).required()
});

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', asyncHandler(async (req, res) => {
  // Validate input
  const { error, value } = registerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const { username, email, password, walletAddress, firstName, lastName, organization } = value;

  // Check if user already exists
  const existingUser = await User.findOne({
    $or: [{ username }, { email }]
  });

  if (existingUser) {
    await logSecurityEvent('security_registration_attempt', req, {
      success: false,
      reason: 'User already exists',
      username,
      email
    });

    return res.status(400).json({
      success: false,
      error: {
        message: 'User with this username or email already exists',
        code: 'USER_EXISTS'
      }
    });
  }

  // Validate wallet address if provided
  if (walletAddress && !isValidAddress(walletAddress)) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Invalid wallet address format',
        code: 'INVALID_WALLET_ADDRESS'
      }
    });
  }

  // Create new user
  const user = new User({
    username,
    email,
    passwordHash: password, // Will be hashed by pre-save middleware
    walletAddress,
    profile: {
      firstName,
      lastName,
      organization
    }
  });

  await user.save();

  // Log successful registration
  await AuditLog.createLog({
    user: user._id,
    action: 'user_register',
    category: 'authentication',
    severity: 'info',
    status: 'success',
    description: `User registered: ${username}`,
    metadata: {
      username,
      email,
      hasWalletAddress: !!walletAddress
    },
    clientInfo: {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    }
  });

  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        walletAddress: user.walletAddress,
        profile: user.profile,
        createdAt: user.createdAt
      }
    }
  });
}));

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', asyncHandler(async (req, res) => {
  // Validate input
  const { error, value } = loginSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const { identifier, password, walletAddress } = value;

  // Find user by username or email
  const user = await User.findByUsernameOrEmail(identifier);

  if (!user) {
    await logSecurityEvent('security_login_failed', req, {
      success: false,
      reason: 'User not found',
      identifier
    });

    return res.status(401).json({
      success: false,
      error: {
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      }
    });
  }

  // Check if account is locked
  if (user.isLocked) {
    await logSecurityEvent('security_login_failed', req, {
      success: false,
      reason: 'Account locked',
      username: user.username
    });

    return res.status(423).json({
      success: false,
      error: {
        message: 'Account is temporarily locked due to multiple failed login attempts',
        code: 'ACCOUNT_LOCKED'
      }
    });
  }

  // Check if account is active
  if (!user.isActive) {
    await logSecurityEvent('security_login_failed', req, {
      success: false,
      reason: 'Account deactivated',
      username: user.username
    });

    return res.status(401).json({
      success: false,
      error: {
        message: 'Account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      }
    });
  }

  // Verify password
  const isPasswordValid = await user.comparePassword(password);

  if (!isPasswordValid) {
    // Increment login attempts
    await user.incLoginAttempts();

    await logSecurityEvent('security_login_failed', req, {
      success: false,
      reason: 'Invalid password',
      username: user.username
    });

    return res.status(401).json({
      success: false,
      error: {
        message: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS'
      }
    });
  }

  // Verify wallet address if provided
  if (walletAddress && user.walletAddress && 
      user.walletAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    await logSecurityEvent('security_login_failed', req, {
      success: false,
      reason: 'Wallet address mismatch',
      username: user.username
    });

    return res.status(401).json({
      success: false,
      error: {
        message: 'Wallet address mismatch',
        code: 'WALLET_ADDRESS_MISMATCH'
      }
    });
  }

  // Reset login attempts on successful login
  await user.resetLoginAttempts();

  // Generate JWT token
  const token = jwt.sign(
    {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      walletAddress: user.walletAddress
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '12h' }
  );

  // Log successful login
  await AuditLog.createLog({
    user: user._id,
    action: 'user_login',
    category: 'authentication',
    severity: 'info',
    status: 'success',
    description: `User logged in: ${user.username}`,
    metadata: {
      username: user.username,
      walletAddress: user.walletAddress
    },
    clientInfo: {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    },
    sessionInfo: {
      userId: user._id,
      walletAddress: user.walletAddress,
      loginTime: new Date()
    }
  });

  res.json({
    success: true,
    message: 'Login successful',
    data: {
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        walletAddress: user.walletAddress,
        profile: user.profile,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    }
  });
}));

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (client-side token removal, server-side logging)
 * @access  Private
 */
router.post('/logout', require('../middleware/auth').requireAuth, asyncHandler(async (req, res) => {
  // Log logout
  await AuditLog.createLog({
    user: req.user.id,
    action: 'user_logout',
    category: 'authentication',
    severity: 'info',
    status: 'success',
    description: `User logged out: ${req.user.username}`,
    metadata: {
      username: req.user.username
    },
    clientInfo: {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    }
  });

  res.json({
    success: true,
    message: 'Logout successful'
  });
}));

/**
 * @route   GET /api/auth/profile
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/profile', require('../middleware/auth').requireAuth, asyncHandler(async (req, res) => {
  const user = await User.findById(req.user.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      }
    });
  }

  res.json({
    success: true,
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        walletAddress: user.walletAddress,
        profile: user.profile,
        isActive: user.isActive,
        isEmailVerified: user.isEmailVerified,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }
    }
  });
}));

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put('/profile', require('../middleware/auth').requireAuth, asyncHandler(async (req, res) => {
  // Validate input
  const { error, value } = updateProfileSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const { firstName, lastName, organization, bio, walletAddress } = value;

  // Validate wallet address if provided
  if (walletAddress && !isValidAddress(walletAddress)) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Invalid wallet address format',
        code: 'INVALID_WALLET_ADDRESS'
      }
    });
  }

  const user = await User.findById(req.user.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      }
    });
  }

  // Update profile fields
  if (firstName !== undefined) user.profile.firstName = firstName;
  if (lastName !== undefined) user.profile.lastName = lastName;
  if (organization !== undefined) user.profile.organization = organization;
  if (bio !== undefined) user.profile.bio = bio;
  if (walletAddress !== undefined) user.walletAddress = walletAddress;

  await user.save();

  // Log profile update
  await AuditLog.createLog({
    user: user._id,
    action: 'user_update_profile',
    category: 'user_management',
    severity: 'info',
    status: 'success',
    description: `Profile updated: ${user.username}`,
    metadata: {
      updatedFields: Object.keys(value),
      walletAddressChanged: !!walletAddress
    },
    clientInfo: {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    }
  });

  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: {
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        walletAddress: user.walletAddress,
        profile: user.profile,
        updatedAt: user.updatedAt
      }
    }
  });
}));

/**
 * @route   PUT /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.put('/change-password', require('../middleware/auth').requireAuth, asyncHandler(async (req, res) => {
  // Validate input
  const { error, value } = changePasswordSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const { currentPassword, newPassword } = value;

  const user = await User.findById(req.user.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'User not found',
        code: 'USER_NOT_FOUND'
      }
    });
  }

  // Verify current password
  const isCurrentPasswordValid = await user.comparePassword(currentPassword);

  if (!isCurrentPasswordValid) {
    await logSecurityEvent('security_password_change_failed', req, {
      success: false,
      reason: 'Invalid current password',
      username: user.username
    });

    return res.status(401).json({
      success: false,
      error: {
        message: 'Current password is incorrect',
        code: 'INVALID_CURRENT_PASSWORD'
      }
    });
  }

  // Update password
  user.passwordHash = newPassword; // Will be hashed by pre-save middleware
  await user.save();

  // Log password change
  await AuditLog.createLog({
    user: user._id,
    action: 'user_change_password',
    category: 'security',
    severity: 'info',
    status: 'success',
    description: `Password changed: ${user.username}`,
    clientInfo: {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    }
  });

  res.json({
    success: true,
    message: 'Password changed successfully'
  });
}));

/**
 * @route   GET /api/auth/verify-token
 * @desc    Verify JWT token validity
 * @access  Private
 */
router.get('/verify-token', require('../middleware/auth').requireAuth, asyncHandler(async (req, res) => {
  res.json({
    success: true,
    message: 'Token is valid',
    data: {
      user: {
        id: req.user.id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role,
        walletAddress: req.user.walletAddress
      }
    }
  });
}));

module.exports = router;
