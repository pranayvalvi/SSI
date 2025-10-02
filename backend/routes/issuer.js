const express = require('express');
const Joi = require('joi');
const Issuer = require('../models/Issuer');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { asyncHandler } = require('../middleware/errorHandler');
const { requireAuth, requireRole } = require('../middleware/auth');
const { pinIssuerMetadata } = require('../utils/pinata');
const { isValidAddress, isIssuerRegistered } = require('../utils/blockchain');

const router = express.Router();

// Validation schemas
const registerIssuerSchema = Joi.object({
  name: Joi.string().min(2).max(100).required(),
  description: Joi.string().max(500).optional(),
  website: Joi.string().uri().optional(),
  logo: Joi.string().uri().optional(),
  capabilities: Joi.array().items(
    Joi.string().valid(
      'identity_verification',
      'educational_credentials', 
      'professional_certifications',
      'health_records',
      'financial_verification',
      'government_id',
      'custom'
    )
  ).min(1).required(),
  contactInfo: Joi.object({
    email: Joi.string().email().optional(),
    phone: Joi.string().optional(),
    address: Joi.object({
      street: Joi.string().optional(),
      city: Joi.string().optional(),
      state: Joi.string().optional(),
      country: Joi.string().optional(),
      postalCode: Joi.string().optional()
    }).optional()
  }).optional(),
  registrationData: Joi.object({
    businessRegistration: Joi.string().optional(),
    taxId: Joi.string().optional(),
    licenseNumber: Joi.string().optional(),
    regulatoryBody: Joi.string().optional()
  }).optional()
});

const updateIssuerSchema = Joi.object({
  name: Joi.string().min(2).max(100).optional(),
  description: Joi.string().max(500).optional(),
  website: Joi.string().uri().optional(),
  logo: Joi.string().uri().optional(),
  capabilities: Joi.array().items(
    Joi.string().valid(
      'identity_verification',
      'educational_credentials',
      'professional_certifications', 
      'health_records',
      'financial_verification',
      'government_id',
      'custom'
    )
  ).min(1).optional(),
  contactInfo: Joi.object({
    email: Joi.string().email().optional(),
    phone: Joi.string().optional(),
    address: Joi.object({
      street: Joi.string().optional(),
      city: Joi.string().optional(),
      state: Joi.string().optional(),
      country: Joi.string().optional(),
      postalCode: Joi.string().optional()
    }).optional()
  }).optional(),
  registrationData: Joi.object({
    businessRegistration: Joi.string().optional(),
    taxId: Joi.string().optional(),
    licenseNumber: Joi.string().optional(),
    regulatoryBody: Joi.string().optional()
  }).optional()
});

/**
 * @route   POST /api/issuers/register
 * @desc    Register as an issuer
 * @access  Private
 */
router.post('/register', requireAuth, asyncHandler(async (req, res) => {
  // Validate input
  const { error, value } = registerIssuerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
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

  if (!user.walletAddress) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Wallet address is required to become an issuer',
        code: 'WALLET_ADDRESS_REQUIRED'
      }
    });
  }

  // Check if user is already an issuer
  const existingIssuer = await Issuer.findOne({ user: user._id });
  if (existingIssuer) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'User is already registered as an issuer',
        code: 'ALREADY_ISSUER'
      }
    });
  }

  const {
    name,
    description,
    website,
    logo,
    capabilities,
    contactInfo,
    registrationData
  } = value;

  try {
    // Prepare metadata for IPFS
    const issuerData = {
      name,
      description,
      website,
      logo,
      capabilities,
      contactInfo,
      registrationData,
      blockchainAddress: user.walletAddress,
      owner: user.username
    };

    // Pin metadata to IPFS
    const ipfsResult = await pinIssuerMetadata(issuerData);
    const metadataUri = `ipfs://${ipfsResult.ipfsHash}`;

    // Create issuer record
    const issuer = new Issuer({
      user: user._id,
      name,
      description,
      website,
      logo,
      metadataUri,
      blockchainAddress: user.walletAddress,
      capabilities,
      contactInfo,
      registrationData,
      status: 'pending' // Requires admin approval or on-chain registration
    });

    await issuer.save();

    // Update user role
    user.role = 'issuer';
    await user.save();

    // Log issuer registration
    await AuditLog.createLog({
      user: user._id,
      issuer: issuer._id,
      action: 'issuer_register',
      category: 'issuer_management',
      severity: 'info',
      status: 'success',
      description: `Issuer registered: ${name}`,
      metadata: {
        issuerName: name,
        capabilities: capabilities,
        metadataUri: metadataUri,
        ipfsHash: ipfsResult.ipfsHash
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.status(201).json({
      success: true,
      message: 'Issuer registration successful. Please complete on-chain registration.',
      data: {
        issuer: {
          id: issuer._id,
          name: issuer.name,
          description: issuer.description,
          metadataUri: issuer.metadataUri,
          blockchainAddress: issuer.blockchainAddress,
          status: issuer.status,
          capabilities: issuer.capabilities,
          createdAt: issuer.createdAt
        },
        nextSteps: {
          message: 'Complete registration by calling registerIssuer on the smart contract',
          contractFunction: 'registerIssuer',
          parameters: {
            issuerAddr: user.walletAddress,
            metadataUri: metadataUri
          }
        }
      }
    });

  } catch (error) {
    console.error('Issuer registration error:', error);
    
    // Log failed registration
    await AuditLog.createLog({
      user: user._id,
      action: 'issuer_register',
      category: 'issuer_management',
      severity: 'error',
      status: 'failure',
      description: `Issuer registration failed: ${error.message}`,
      metadata: {
        issuerName: name,
        error: error.message
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    throw error;
  }
}));

/**
 * @route   PUT /api/issuers/:id
 * @desc    Update issuer information
 * @access  Private (Issuer or Admin)
 */
router.put('/:id', requireAuth, asyncHandler(async (req, res) => {
  // Validate input
  const { error, value } = updateIssuerSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const issuer = await Issuer.findById(req.params.id).populate('user');
  
  if (!issuer) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'Issuer not found',
        code: 'ISSUER_NOT_FOUND'
      }
    });
  }

  // Check permissions (issuer owner or admin)
  if (issuer.user._id.toString() !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      error: {
        message: 'Access denied. You can only update your own issuer profile.',
        code: 'ACCESS_DENIED'
      }
    });
  }

  const updatedFields = [];
  
  // Update fields
  Object.keys(value).forEach(key => {
    if (value[key] !== undefined) {
      issuer[key] = value[key];
      updatedFields.push(key);
    }
  });

  try {
    // If significant fields changed, update IPFS metadata
    const significantFields = ['name', 'description', 'website', 'logo', 'capabilities', 'contactInfo'];
    const shouldUpdateIPFS = updatedFields.some(field => significantFields.includes(field));

    if (shouldUpdateIPFS) {
      const issuerData = {
        name: issuer.name,
        description: issuer.description,
        website: issuer.website,
        logo: issuer.logo,
        capabilities: issuer.capabilities,
        contactInfo: issuer.contactInfo,
        registrationData: issuer.registrationData,
        blockchainAddress: issuer.blockchainAddress,
        owner: issuer.user.username,
        updatedAt: new Date().toISOString()
      };

      const ipfsResult = await pinIssuerMetadata(issuerData);
      issuer.metadataUri = `ipfs://${ipfsResult.ipfsHash}`;
    }

    await issuer.save();

    // Log issuer update
    await AuditLog.createLog({
      user: req.user.id,
      issuer: issuer._id,
      action: 'issuer_update',
      category: 'issuer_management',
      severity: 'info',
      status: 'success',
      description: `Issuer updated: ${issuer.name}`,
      metadata: {
        updatedFields: updatedFields,
        metadataUpdated: shouldUpdateIPFS,
        newMetadataUri: shouldUpdateIPFS ? issuer.metadataUri : undefined
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.json({
      success: true,
      message: 'Issuer updated successfully',
      data: {
        issuer: {
          id: issuer._id,
          name: issuer.name,
          description: issuer.description,
          metadataUri: issuer.metadataUri,
          blockchainAddress: issuer.blockchainAddress,
          status: issuer.status,
          capabilities: issuer.capabilities,
          contactInfo: issuer.contactInfo,
          updatedAt: issuer.updatedAt
        },
        updatedFields: updatedFields,
        ...(shouldUpdateIPFS && {
          nextSteps: {
            message: 'Update on-chain metadata by calling updateIssuer on the smart contract',
            contractFunction: 'updateIssuer',
            parameters: {
              issuerAddr: issuer.blockchainAddress,
              metadataUri: issuer.metadataUri
            }
          }
        })
      }
    });

  } catch (error) {
    console.error('Issuer update error:', error);
    throw error;
  }
}));

/**
 * @route   POST /api/issuers/:id/confirm-registration
 * @desc    Confirm on-chain registration completion
 * @access  Private (Issuer owner)
 */
router.post('/:id/confirm-registration', requireAuth, asyncHandler(async (req, res) => {
  const { txHash, blockNumber } = req.body;

  if (!txHash) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Transaction hash is required',
        code: 'TX_HASH_REQUIRED'
      }
    });
  }

  const issuer = await Issuer.findById(req.params.id).populate('user');
  
  if (!issuer) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'Issuer not found',
        code: 'ISSUER_NOT_FOUND'
      }
    });
  }

  // Check permissions
  if (issuer.user._id.toString() !== req.user.id) {
    return res.status(403).json({
      success: false,
      error: {
        message: 'Access denied',
        code: 'ACCESS_DENIED'
      }
    });
  }

  try {
    // Verify on-chain registration
    const isRegistered = await isIssuerRegistered(issuer.blockchainAddress);
    
    if (!isRegistered) {
      return res.status(400).json({
        success: false,
        error: {
          message: 'On-chain registration not found. Please ensure the transaction was successful.',
          code: 'REGISTRATION_NOT_FOUND'
        }
      });
    }

    // Update issuer status
    issuer.status = 'active';
    issuer.onChainData.isOnChainRegistered = true;
    issuer.onChainData.registrationTxHash = txHash;
    issuer.onChainData.registrationBlockNumber = blockNumber;

    await issuer.save();

    // Log registration confirmation
    await AuditLog.createLog({
      user: req.user.id,
      issuer: issuer._id,
      action: 'issuer_registration_confirmed',
      category: 'issuer_management',
      severity: 'info',
      status: 'success',
      description: `On-chain registration confirmed: ${issuer.name}`,
      metadata: {
        issuerName: issuer.name,
        txHash: txHash,
        blockNumber: blockNumber
      },
      blockchainData: {
        network: 'sepolia',
        txHash: txHash,
        blockNumber: blockNumber,
        contractAddress: process.env.CONTRACT_ADDRESS
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.json({
      success: true,
      message: 'On-chain registration confirmed successfully',
      data: {
        issuer: {
          id: issuer._id,
          name: issuer.name,
          status: issuer.status,
          onChainData: issuer.onChainData
        }
      }
    });

  } catch (error) {
    console.error('Registration confirmation error:', error);
    throw error;
  }
}));

/**
 * @route   GET /api/issuers
 * @desc    Get all active issuers
 * @access  Public
 */
router.get('/', asyncHandler(async (req, res) => {
  const { page = 1, limit = 20, status, capabilities } = req.query;
  
  const query = {};
  
  if (status) {
    query.status = status;
  } else {
    query.status = 'active'; // Default to active issuers
  }
  
  if (capabilities) {
    query.capabilities = { $in: capabilities.split(',') };
  }

  const options = {
    page: parseInt(page),
    limit: parseInt(limit),
    sort: { createdAt: -1 },
    populate: {
      path: 'user',
      select: 'username profile.organization'
    }
  };

  const result = await Issuer.paginate(query, options);

  res.json({
    success: true,
    data: {
      issuers: result.docs.map(issuer => ({
        id: issuer._id,
        name: issuer.name,
        description: issuer.description,
        website: issuer.website,
        logo: issuer.logo,
        capabilities: issuer.capabilities,
        verificationLevel: issuer.verificationLevel,
        reputationScore: issuer.reputationScore,
        statistics: issuer.statistics,
        createdAt: issuer.createdAt,
        user: {
          username: issuer.user.username,
          organization: issuer.user.profile?.organization
        }
      })),
      pagination: {
        currentPage: result.page,
        totalPages: result.totalPages,
        totalDocs: result.totalDocs,
        limit: result.limit,
        hasNextPage: result.hasNextPage,
        hasPrevPage: result.hasPrevPage
      }
    }
  });
}));

/**
 * @route   GET /api/issuers/:id
 * @desc    Get issuer by ID
 * @access  Public
 */
router.get('/:id', asyncHandler(async (req, res) => {
  const issuer = await Issuer.findById(req.params.id)
    .populate('user', 'username profile.organization createdAt');

  if (!issuer) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'Issuer not found',
        code: 'ISSUER_NOT_FOUND'
      }
    });
  }

  res.json({
    success: true,
    data: {
      issuer: {
        id: issuer._id,
        name: issuer.name,
        description: issuer.description,
        website: issuer.website,
        logo: issuer.logo,
        capabilities: issuer.capabilities,
        contactInfo: issuer.contactInfo,
        verificationLevel: issuer.verificationLevel,
        reputationScore: issuer.reputationScore,
        statistics: issuer.statistics,
        status: issuer.status,
        createdAt: issuer.createdAt,
        user: {
          username: issuer.user.username,
          organization: issuer.user.profile?.organization,
          memberSince: issuer.user.createdAt
        }
      }
    }
  });
}));

/**
 * @route   GET /api/issuers/my/profile
 * @desc    Get current user's issuer profile
 * @access  Private (Issuer)
 */
router.get('/my/profile', requireAuth, asyncHandler(async (req, res) => {
  const issuer = await Issuer.findOne({ user: req.user.id })
    .populate('user', 'username email profile');

  if (!issuer) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'Issuer profile not found',
        code: 'ISSUER_NOT_FOUND'
      }
    });
  }

  res.json({
    success: true,
    data: {
      issuer: {
        id: issuer._id,
        name: issuer.name,
        description: issuer.description,
        website: issuer.website,
        logo: issuer.logo,
        metadataUri: issuer.metadataUri,
        blockchainAddress: issuer.blockchainAddress,
        capabilities: issuer.capabilities,
        contactInfo: issuer.contactInfo,
        registrationData: issuer.registrationData,
        verificationLevel: issuer.verificationLevel,
        reputationScore: issuer.reputationScore,
        statistics: issuer.statistics,
        settings: issuer.settings,
        status: issuer.status,
        onChainData: issuer.onChainData,
        createdAt: issuer.createdAt,
        updatedAt: issuer.updatedAt,
        user: issuer.user
      }
    }
  });
}));

module.exports = router;
