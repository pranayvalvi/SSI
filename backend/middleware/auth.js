const jwt = require('jsonwebtoken');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');

/**
 * Middleware to authenticate JWT tokens
 */
const requireAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Access denied. No token provided.',
        code: 'NO_TOKEN'
      });
    }
    
    const token = authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({
        error: 'Access denied. Invalid token format.',
        code: 'INVALID_TOKEN_FORMAT'
      });
    }
    
    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Find user and check if still active
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json({
        error: 'Access denied. User not found.',
        code: 'USER_NOT_FOUND'
      });
    }
    
    if (!user.isActive) {
      return res.status(401).json({
        error: 'Access denied. Account is deactivated.',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }
    
    if (user.isLocked) {
      return res.status(401).json({
        error: 'Access denied. Account is locked.',
        code: 'ACCOUNT_LOCKED'
      });
    }
    
    // Add user info to request
    req.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      walletAddress: user.walletAddress
    };
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Access denied. Invalid token.',
        code: 'INVALID_TOKEN'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Access denied. Token expired.',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    console.error('Auth middleware error:', error);
    res.status(500).json({
      error: 'Internal server error during authentication.',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * Middleware to check if user has required role
 */
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required.',
        code: 'AUTH_REQUIRED'
      });
    }
    
    const userRoles = Array.isArray(req.user.role) ? req.user.role : [req.user.role];
    const requiredRoles = Array.isArray(roles) ? roles : [roles];
    
    const hasRole = requiredRoles.some(role => userRoles.includes(role));
    
    if (!hasRole) {
      // Log unauthorized access attempt
      AuditLog.createLog({
        user: req.user.id,
        action: 'security_unauthorized_access',
        category: 'security',
        severity: 'warning',
        status: 'failure',
        description: `Unauthorized access attempt to ${req.method} ${req.path}`,
        metadata: {
          requiredRoles: requiredRoles,
          userRole: req.user.role,
          endpoint: `${req.method} ${req.path}`
        },
        clientInfo: {
          ipAddress: req.ip || req.connection.remoteAddress,
          userAgent: req.get('User-Agent')
        },
        requestData: {
          method: req.method,
          url: req.originalUrl,
          headers: req.headers
        }
      });
      
      return res.status(403).json({
        error: 'Access denied. Insufficient permissions.',
        code: 'INSUFFICIENT_PERMISSIONS',
        required: requiredRoles,
        current: req.user.role
      });
    }
    
    next();
  };
};

/**
 * Middleware to check if user is an issuer
 */
const requireIssuer = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        error: 'Authentication required.',
        code: 'AUTH_REQUIRED'
      });
    }
    
    const Issuer = require('../models/Issuer');
    const issuer = await Issuer.findOne({ 
      user: req.user.id,
      status: 'active'
    });
    
    if (!issuer) {
      return res.status(403).json({
        error: 'Access denied. Active issuer status required.',
        code: 'ISSUER_STATUS_REQUIRED'
      });
    }
    
    if (!issuer.canIssueCredentials()) {
      return res.status(403).json({
        error: 'Access denied. Issuer not authorized to issue credentials.',
        code: 'ISSUER_NOT_AUTHORIZED'
      });
    }
    
    // Add issuer info to request
    req.issuer = issuer;
    
    next();
  } catch (error) {
    console.error('Issuer middleware error:', error);
    res.status(500).json({
      error: 'Internal server error during issuer verification.',
      code: 'ISSUER_VERIFICATION_ERROR'
    });
  }
};

/**
 * Middleware to validate wallet address ownership
 */
const requireWalletOwnership = (req, res, next) => {
  const { walletAddress } = req.body;
  
  if (!walletAddress) {
    return res.status(400).json({
      error: 'Wallet address is required.',
      code: 'WALLET_ADDRESS_REQUIRED'
    });
  }
  
  if (req.user.walletAddress && req.user.walletAddress.toLowerCase() !== walletAddress.toLowerCase()) {
    return res.status(403).json({
      error: 'Access denied. Wallet address mismatch.',
      code: 'WALLET_ADDRESS_MISMATCH'
    });
  }
  
  next();
};

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }
    
    const token = authHeader.split(' ')[1];
    
    if (!token) {
      return next();
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    
    if (user && user.isActive && !user.isLocked) {
      req.user = {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        walletAddress: user.walletAddress
      };
    }
    
    next();
  } catch (error) {
    // Ignore auth errors in optional auth
    next();
  }
};

/**
 * Middleware to check API key for external integrations
 */
const requireApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({
      error: 'API key required.',
      code: 'API_KEY_REQUIRED'
    });
  }
  
  // In production, validate against stored API keys
  const validApiKeys = process.env.VALID_API_KEYS?.split(',') || [];
  
  if (!validApiKeys.includes(apiKey)) {
    return res.status(401).json({
      error: 'Invalid API key.',
      code: 'INVALID_API_KEY'
    });
  }
  
  next();
};

module.exports = {
  requireAuth,
  requireRole,
  requireIssuer,
  requireWalletOwnership,
  optionalAuth,
  requireApiKey
};
