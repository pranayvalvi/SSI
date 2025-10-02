const crypto = require('crypto');

/**
 * Simple CSRF protection middleware
 */
const csrfProtection = {
  // Generate CSRF token
  generateToken: () => {
    return crypto.randomBytes(32).toString('hex');
  },

  // Middleware to add CSRF token to session/response
  addToken: (req, res, next) => {
    if (!req.session) {
      req.session = {};
    }
    
    if (!req.session.csrfToken) {
      req.session.csrfToken = csrfProtection.generateToken();
    }
    
    res.locals.csrfToken = req.session.csrfToken;
    next();
  },

  // Middleware to verify CSRF token
  verifyToken: (req, res, next) => {
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    const sessionToken = req.session?.csrfToken;

    if (!token || !sessionToken || token !== sessionToken) {
      return res.status(403).json({
        success: false,
        error: {
          message: 'Invalid CSRF token',
          code: 'CSRF_TOKEN_INVALID'
        }
      });
    }

    next();
  }
};

module.exports = csrfProtection;