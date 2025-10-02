const express = require('express');
const Joi = require('joi');
const Credential = require('../models/Credential');
const Issuer = require('../models/Issuer');
const AuditLog = require('../models/AuditLog');
const { asyncHandler } = require('../middleware/errorHandler');
const { requireAuth, requireIssuer } = require('../middleware/auth');
const { pinCredentialMetadata } = require('../utils/pinata');
const { generateCredentialHash, verifySignature } = require('../utils/blockchain');

const router = express.Router();

// Validation schemas
const issueCredentialSchema = Joi.object({
  subject: Joi.string().required(),
  subjectAddress: Joi.string().pattern(/^0x[a-fA-F0-9]{40}$/).optional(),
  credentialType: Joi.string().valid(
    'IdentityCredential',
    'EducationalCredential', 
    'ProfessionalCredential',
    'HealthCredential',
    'FinancialCredential',
    'GovernmentCredential',
    'CustomCredential'
  ).required(),
  vc: Joi.object({
    '@context': Joi.array().items(Joi.string()).required(),
    id: Joi.string().required(),
    type: Joi.array().items(Joi.string()).required(),
    issuer: Joi.string().required(),
    issuanceDate: Joi.string().isoDate().required(),
    credentialSubject: Joi.object().required(),
    proof: Joi.object({
      type: Joi.string().optional(),
      created: Joi.string().isoDate().optional(),
      proofPurpose: Joi.string().optional(),
      verificationMethod: Joi.string().optional(),
      jws: Joi.string().optional(),
      signature: Joi.string().optional()
    }).optional()
  }).required(),
  expirationDate: Joi.string().isoDate().optional(),
  metadata: Joi.object({
    tags: Joi.array().items(Joi.string()).optional(),
    category: Joi.string().optional(),
    priority: Joi.string().valid('low', 'medium', 'high', 'critical').optional(),
    confidentialityLevel: Joi.string().valid('public', 'internal', 'confidential', 'restricted').optional()
  }).optional()
});

const verifyCredentialSchema = Joi.object({
  credentialHash: Joi.string().pattern(/^0x[a-fA-F0-9]{64}$/).optional(),
  vc: Joi.object().optional(),
  signature: Joi.string().optional(),
  challenge: Joi.string().optional()
}).or('credentialHash', 'vc');

/**
 * @route   POST /api/credentials/issue
 * @desc    Issue a new verifiable credential
 * @access  Private (Issuer)
 */
router.post('/issue', requireAuth, requireIssuer, asyncHandler(async (req, res) => {
  // Validate input
  const { error, value } = issueCredentialSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const {
    subject,
    subjectAddress,
    credentialType,
    vc,
    expirationDate,
    metadata
  } = value;

  try {
    // Verify issuer can issue this type of credential
    const issuer = req.issuer;
    
    if (!issuer.canIssueCredentials()) {
      return res.status(403).json({
        success: false,
        error: {
          message: 'Issuer is not authorized to issue credentials',
          code: 'ISSUER_NOT_AUTHORIZED'
        }
      });
    }

    // Generate credential hash
    const credentialHash = generateCredentialHash(vc);

    // Check for duplicate credential
    const existingCredential = await Credential.findByHash(credentialHash);
    if (existingCredential) {
      return res.status(400).json({
        success: false,
        error: {
          message: 'Credential with this hash already exists',
          code: 'DUPLICATE_CREDENTIAL'
        }
      });
    }

    // Prepare credential data for IPFS
    const credentialData = {
      vc,
      issuerMetadataUri: issuer.metadataUri,
      subject,
      credentialHash,
      issuedAt: new Date().toISOString()
    };

    // Pin credential metadata to IPFS
    const ipfsResult = await pinCredentialMetadata(credentialData);

    // Create credential record
    const credential = new Credential({
      issuer: issuer._id,
      subject,
      subjectAddress,
      credentialType,
      vc,
      ipfsHash: ipfsResult.ipfsHash,
      credentialHash,
      expirationDate: expirationDate ? new Date(expirationDate) : undefined,
      metadata: metadata || {},
      proofData: vc.proof || {}
    });

    await credential.save();

    // Update issuer statistics
    await issuer.incrementCredentialsIssued();

    // Log credential issuance
    await AuditLog.createLog({
      user: req.user.id,
      issuer: issuer._id,
      credential: credential._id,
      action: 'credential_issue',
      category: 'credential_management',
      severity: 'info',
      status: 'success',
      description: `Credential issued: ${credentialType}`,
      metadata: {
        credentialType,
        subject,
        credentialHash,
        ipfsHash: ipfsResult.ipfsHash,
        hasExpiration: !!expirationDate
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.status(201).json({
      success: true,
      message: 'Credential issued successfully',
      data: {
        credential: {
          id: credential._id,
          credentialHash: credential.credentialHash,
          ipfsHash: credential.ipfsHash,
          credentialType: credential.credentialType,
          subject: credential.subject,
          subjectAddress: credential.subjectAddress,
          status: credential.status,
          issuedAt: credential.createdAt,
          expirationDate: credential.expirationDate
        },
        ipfsUri: `ipfs://${ipfsResult.ipfsHash}`,
        verificationInfo: {
          credentialHash: credentialHash,
          issuerAddress: issuer.blockchainAddress,
          verificationEndpoint: `/api/credentials/verify`
        }
      }
    });

  } catch (error) {
    console.error('Credential issuance error:', error);
    
    // Log failed issuance
    await AuditLog.createLog({
      user: req.user.id,
      issuer: req.issuer._id,
      action: 'credential_issue',
      category: 'credential_management',
      severity: 'error',
      status: 'failure',
      description: `Credential issuance failed: ${error.message}`,
      metadata: {
        credentialType,
        subject,
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
 * @route   POST /api/credentials/verify
 * @desc    Verify a credential
 * @access  Public
 */
router.post('/verify', asyncHandler(async (req, res) => {
  // Validate input
  const { error, value } = verifyCredentialSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const { credentialHash, vc, signature, challenge } = value;

  try {
    let credential;
    let verificationResult = {
      isValid: false,
      checks: {
        credentialExists: false,
        issuerRegistered: false,
        notRevoked: false,
        notExpired: false,
        signatureValid: false
      },
      details: {}
    };

    // Find credential by hash or generate hash from VC
    if (credentialHash) {
      credential = await Credential.findByHash(credentialHash)
        .populate('issuer', 'name blockchainAddress metadataUri status onChainData');
    } else if (vc) {
      const hash = generateCredentialHash(vc);
      credential = await Credential.findByHash(hash)
        .populate('issuer', 'name blockchainAddress metadataUri status onChainData');
    }

    if (credential) {
      verificationResult.checks.credentialExists = true;
      verificationResult.details.credential = {
        id: credential._id,
        type: credential.credentialType,
        issuer: credential.issuer.name,
        issuedAt: credential.createdAt,
        status: credential.status
      };

      // Check if issuer is registered and active
      const issuer = credential.issuer;
      if (issuer.status === 'active' && issuer.onChainData.isOnChainRegistered) {
        verificationResult.checks.issuerRegistered = true;
      }

      // Check if credential is not revoked
      if (credential.status === 'valid') {
        verificationResult.checks.notRevoked = true;
      }

      // Check if credential is not expired
      if (!credential.isExpired) {
        verificationResult.checks.notExpired = true;
      }

      // Verify signature if provided
      if (signature && vc) {
        const message = JSON.stringify(vc, Object.keys(vc).sort());
        const isSignatureValid = verifySignature(message, signature, issuer.blockchainAddress);
        verificationResult.checks.signatureValid = isSignatureValid;
      }

      // Record verification attempt
      await credential.recordVerification(
        req.ip || 'unknown',
        verificationResult.checks.notRevoked && verificationResult.checks.notExpired ? 'valid' : 'invalid',
        req.ip || req.connection.remoteAddress,
        req.get('User-Agent')
      );
    }

    // Overall validity check
    verificationResult.isValid = Object.values(verificationResult.checks).every(check => check === true);

    // Log verification attempt
    await AuditLog.createLog({
      credential: credential?._id,
      issuer: credential?.issuer._id,
      action: 'credential_verify',
      category: 'verification',
      severity: 'info',
      status: verificationResult.isValid ? 'success' : 'failure',
      description: `Credential verification: ${verificationResult.isValid ? 'VALID' : 'INVALID'}`,
      metadata: {
        credentialHash: credentialHash || generateCredentialHash(vc),
        verificationResult: verificationResult,
        hasSignature: !!signature,
        hasChallenge: !!challenge
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.json({
      success: true,
      data: {
        verification: verificationResult,
        timestamp: new Date().toISOString(),
        verifier: 'SSI Verification Service'
      }
    });

  } catch (error) {
    console.error('Credential verification error:', error);
    
    // Log verification error
    await AuditLog.createLog({
      action: 'credential_verify',
      category: 'verification',
      severity: 'error',
      status: 'failure',
      description: `Credential verification failed: ${error.message}`,
      metadata: {
        credentialHash,
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
 * @route   POST /api/credentials/:id/revoke
 * @desc    Revoke a credential
 * @access  Private (Issuer who issued the credential)
 */
router.post('/:id/revoke', requireAuth, requireIssuer, asyncHandler(async (req, res) => {
  const { reason, txHash, blockNumber } = req.body;

  const credential = await Credential.findById(req.params.id)
    .populate('issuer', 'user blockchainAddress');

  if (!credential) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'Credential not found',
        code: 'CREDENTIAL_NOT_FOUND'
      }
    });
  }

  // Check if user is the issuer of this credential
  if (credential.issuer._id.toString() !== req.issuer._id.toString()) {
    return res.status(403).json({
      success: false,
      error: {
        message: 'Access denied. You can only revoke credentials you issued.',
        code: 'ACCESS_DENIED'
      }
    });
  }

  if (credential.status === 'revoked') {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Credential is already revoked',
        code: 'ALREADY_REVOKED'
      }
    });
  }

  try {
    // Revoke credential
    await credential.revoke(req.user.id, reason, txHash, blockNumber);

    // Update issuer statistics
    await req.issuer.incrementCredentialsRevoked();

    // Log revocation
    await AuditLog.createLog({
      user: req.user.id,
      issuer: req.issuer._id,
      credential: credential._id,
      action: 'credential_revoke',
      category: 'credential_management',
      severity: 'warning',
      status: 'success',
      description: `Credential revoked: ${credential.credentialType}`,
      metadata: {
        credentialHash: credential.credentialHash,
        reason: reason || 'unspecified',
        txHash,
        blockNumber
      },
      blockchainData: txHash ? {
        network: 'sepolia',
        txHash,
        blockNumber,
        contractAddress: process.env.CONTRACT_ADDRESS
      } : undefined,
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.json({
      success: true,
      message: 'Credential revoked successfully',
      data: {
        credential: {
          id: credential._id,
          credentialHash: credential.credentialHash,
          status: credential.status,
          revocationData: credential.revocationData
        }
      }
    });

  } catch (error) {
    console.error('Credential revocation error:', error);
    throw error;
  }
}));

/**
 * @route   GET /api/credentials
 * @desc    Get credentials (filtered by query parameters)
 * @access  Private
 */
router.get('/', requireAuth, asyncHandler(async (req, res) => {
  const { 
    page = 1, 
    limit = 20, 
    status, 
    credentialType, 
    issuer: issuerId,
    subject 
  } = req.query;

  const query = {};

  // Filter by status
  if (status) {
    query.status = status;
  }

  // Filter by credential type
  if (credentialType) {
    query.credentialType = credentialType;
  }

  // Filter by issuer (if user is admin) or restrict to user's issued credentials
  if (req.user.role === 'admin' && issuerId) {
    query.issuer = issuerId;
  } else if (req.user.role === 'issuer') {
    const userIssuer = await Issuer.findOne({ user: req.user.id });
    if (userIssuer) {
      query.issuer = userIssuer._id;
    }
  }

  // Filter by subject (if user is admin or the subject themselves)
  if (subject) {
    if (req.user.role === 'admin' || subject === req.user.walletAddress) {
      query.subject = subject;
    }
  } else if (req.user.role === 'user') {
    // Regular users can only see credentials issued to them
    query.subject = req.user.walletAddress || req.user.username;
  }

  const options = {
    page: parseInt(page),
    limit: parseInt(limit),
    sort: { createdAt: -1 },
    populate: {
      path: 'issuer',
      select: 'name blockchainAddress verificationLevel'
    }
  };

  const result = await Credential.paginate(query, options);

  res.json({
    success: true,
    data: {
      credentials: result.docs.map(cred => ({
        id: cred._id,
        credentialHash: cred.credentialHash,
        credentialType: cred.credentialType,
        subject: cred.subject,
        status: cred.status,
        issuedAt: cred.createdAt,
        expirationDate: cred.expirationDate,
        isExpired: cred.isExpired,
        issuer: {
          id: cred.issuer._id,
          name: cred.issuer.name,
          verificationLevel: cred.issuer.verificationLevel
        },
        verificationData: {
          totalVerifications: cred.verificationData.totalVerifications,
          lastVerificationDate: cred.verificationData.lastVerificationDate
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
 * @route   GET /api/credentials/:id
 * @desc    Get credential by ID
 * @access  Private
 */
router.get('/:id', requireAuth, asyncHandler(async (req, res) => {
  const credential = await Credential.findById(req.params.id)
    .populate('issuer', 'name blockchainAddress metadataUri verificationLevel onChainData');

  if (!credential) {
    return res.status(404).json({
      success: false,
      error: {
        message: 'Credential not found',
        code: 'CREDENTIAL_NOT_FOUND'
      }
    });
  }

  // Check access permissions
  const hasAccess = 
    req.user.role === 'admin' ||
    (credential.issuer.user && credential.issuer.user.toString() === req.user.id) ||
    credential.subject === req.user.walletAddress ||
    credential.subject === req.user.username;

  if (!hasAccess) {
    return res.status(403).json({
      success: false,
      error: {
        message: 'Access denied',
        code: 'ACCESS_DENIED'
      }
    });
  }

  res.json({
    success: true,
    data: {
      credential: {
        id: credential._id,
        credentialHash: credential.credentialHash,
        ipfsHash: credential.ipfsHash,
        credentialType: credential.credentialType,
        subject: credential.subject,
        subjectAddress: credential.subjectAddress,
        vc: credential.vc,
        status: credential.status,
        issuedAt: credential.createdAt,
        expirationDate: credential.expirationDate,
        isExpired: credential.isExpired,
        metadata: credential.metadata,
        proofData: credential.proofData,
        revocationData: credential.revocationData,
        verificationData: credential.verificationData,
        issuer: {
          id: credential.issuer._id,
          name: credential.issuer.name,
          blockchainAddress: credential.issuer.blockchainAddress,
          metadataUri: credential.issuer.metadataUri,
          verificationLevel: credential.issuer.verificationLevel,
          isOnChainRegistered: credential.issuer.onChainData.isOnChainRegistered
        }
      }
    }
  });
}));

module.exports = router;
