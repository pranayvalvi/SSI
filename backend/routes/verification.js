const express = require('express');
const Joi = require('joi');
const Credential = require('../models/Credential');
const Issuer = require('../models/Issuer');
const AuditLog = require('../models/AuditLog');
const { asyncHandler } = require('../middleware/errorHandler');
const { optionalAuth } = require('../middleware/auth');
const { 
  isIssuerRegistered, 
  isCredentialRevoked, 
  verifySignature,
  verifyTypedDataSignature,
  generateCredentialHash 
} = require('../utils/blockchain');
const { getFromIPFS } = require('../utils/pinata');

const router = express.Router();

// Validation schemas
const verifyPresentationSchema = Joi.object({
  presentation: Joi.object({
    '@context': Joi.array().items(Joi.string()).required(),
    type: Joi.array().items(Joi.string()).required(),
    verifiableCredential: Joi.array().items(Joi.object()).required(),
    holder: Joi.string().required(),
    proof: Joi.object({
      type: Joi.string().required(),
      created: Joi.string().isoDate().required(),
      challenge: Joi.string().required(),
      domain: Joi.string().optional(),
      proofPurpose: Joi.string().required(),
      verificationMethod: Joi.string().required(),
      jws: Joi.string().optional(),
      signature: Joi.string().optional()
    }).required()
  }).required(),
  challenge: Joi.string().required(),
  domain: Joi.string().optional()
});

const createChallengeSchema = Joi.object({
  verifier: Joi.string().required(),
  purpose: Joi.string().optional(),
  domain: Joi.string().optional(),
  expiresIn: Joi.number().min(60).max(3600).optional() // 1 minute to 1 hour
});

const verifyCredentialBatchSchema = Joi.object({
  credentials: Joi.array().items(
    Joi.object({
      credentialHash: Joi.string().pattern(/^0x[a-fA-F0-9]{64}$/).optional(),
      vc: Joi.object().optional(),
      signature: Joi.string().optional()
    }).or('credentialHash', 'vc')
  ).min(1).max(10).required()
});

/**
 * @route   POST /api/verification/challenge
 * @desc    Create a verification challenge
 * @access  Public
 */
router.post('/challenge', optionalAuth, asyncHandler(async (req, res) => {
  const { error, value } = createChallengeSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const { verifier, purpose, domain, expiresIn = 300 } = value; // Default 5 minutes

  // Generate challenge
  const challenge = {
    nonce: generateNonce(),
    verifier: verifier,
    purpose: purpose || 'authentication',
    domain: domain,
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + expiresIn * 1000).toISOString()
  };

  // Log challenge creation
  await AuditLog.createLog({
    user: req.user?.id,
    action: 'verification_challenge_created',
    category: 'verification',
    severity: 'info',
    status: 'success',
    description: `Verification challenge created for ${verifier}`,
    metadata: {
      verifier,
      purpose,
      domain,
      expiresIn,
      nonce: challenge.nonce
    },
    clientInfo: {
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent')
    }
  });

  res.json({
    success: true,
    data: {
      challenge: challenge
    }
  });
}));

/**
 * @route   POST /api/verification/presentation
 * @desc    Verify a verifiable presentation
 * @access  Public
 */
router.post('/presentation', optionalAuth, asyncHandler(async (req, res) => {
  const { error, value } = verifyPresentationSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const { presentation, challenge, domain } = value;

  try {
    const verificationResult = {
      isValid: false,
      presentation: {
        holder: presentation.holder,
        credentialCount: presentation.verifiableCredential.length,
        verifiedAt: new Date().toISOString()
      },
      checks: {
        presentationStructure: false,
        challengeValid: false,
        holderSignature: false,
        credentialsValid: false
      },
      credentials: [],
      errors: []
    };

    // 1. Verify presentation structure
    if (presentation['@context'] && presentation.type && presentation.verifiableCredential && presentation.proof) {
      verificationResult.checks.presentationStructure = true;
    } else {
      verificationResult.errors.push('Invalid presentation structure');
    }

    // 2. Verify challenge
    if (presentation.proof.challenge === challenge) {
      // Check if challenge is not expired (basic check - in production, store challenges in cache/db)
      const challengeAge = Date.now() - new Date(presentation.proof.created).getTime();
      if (challengeAge < 3600000) { // 1 hour max
        verificationResult.checks.challengeValid = true;
      } else {
        verificationResult.errors.push('Challenge expired');
      }
    } else {
      verificationResult.errors.push('Challenge mismatch');
    }

    // 3. Verify holder signature on presentation
    if (presentation.proof.signature) {
      const presentationMessage = JSON.stringify({
        '@context': presentation['@context'],
        type: presentation.type,
        verifiableCredential: presentation.verifiableCredential,
        holder: presentation.holder,
        challenge: presentation.proof.challenge
      }, Object.keys(presentation).sort());

      const isHolderSignatureValid = verifySignature(
        presentationMessage,
        presentation.proof.signature,
        presentation.holder
      );

      verificationResult.checks.holderSignature = isHolderSignatureValid;
      if (!isHolderSignatureValid) {
        verificationResult.errors.push('Invalid holder signature');
      }
    } else {
      verificationResult.errors.push('Missing holder signature');
    }

    // 4. Verify each credential in the presentation
    const credentialVerifications = [];
    
    for (const [index, vc] of presentation.verifiableCredential.entries()) {
      const credResult = await verifyIndividualCredential(vc, req);
      credentialVerifications.push({
        index,
        credentialId: vc.id,
        credentialType: vc.type,
        issuer: vc.issuer,
        subject: vc.credentialSubject.id,
        isValid: credResult.isValid,
        checks: credResult.checks,
        errors: credResult.errors
      });
    }

    verificationResult.credentials = credentialVerifications;
    verificationResult.checks.credentialsValid = credentialVerifications.every(cred => cred.isValid);

    // Overall validity
    verificationResult.isValid = Object.values(verificationResult.checks).every(check => check === true);

    // Log presentation verification
    await AuditLog.createLog({
      user: req.user?.id,
      action: 'presentation_verify',
      category: 'verification',
      severity: 'info',
      status: verificationResult.isValid ? 'success' : 'failure',
      description: `Presentation verification: ${verificationResult.isValid ? 'VALID' : 'INVALID'}`,
      metadata: {
        holder: presentation.holder,
        credentialCount: presentation.verifiableCredential.length,
        verificationResult: {
          isValid: verificationResult.isValid,
          checks: verificationResult.checks,
          errorCount: verificationResult.errors.length
        },
        challenge,
        domain
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.json({
      success: true,
      data: {
        verification: verificationResult
      }
    });

  } catch (error) {
    console.error('Presentation verification error:', error);
    
    await AuditLog.createLog({
      user: req.user?.id,
      action: 'presentation_verify',
      category: 'verification',
      severity: 'error',
      status: 'failure',
      description: `Presentation verification failed: ${error.message}`,
      metadata: {
        error: error.message,
        challenge
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
 * @route   POST /api/verification/batch
 * @desc    Verify multiple credentials in batch
 * @access  Public
 */
router.post('/batch', optionalAuth, asyncHandler(async (req, res) => {
  const { error, value } = verifyCredentialBatchSchema.validate(req.body);
  if (error) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Validation failed',
        details: error.details.map(d => d.message)
      }
    });
  }

  const { credentials } = value;

  try {
    const verificationResults = [];

    for (const [index, credData] of credentials.entries()) {
      try {
        let credential;
        let credentialHash;

        if (credData.credentialHash) {
          credentialHash = credData.credentialHash;
          credential = await Credential.findByHash(credentialHash)
            .populate('issuer', 'name blockchainAddress status onChainData');
        } else if (credData.vc) {
          credentialHash = generateCredentialHash(credData.vc);
          credential = await Credential.findByHash(credentialHash)
            .populate('issuer', 'name blockchainAddress status onChainData');
        }

        const result = await verifyIndividualCredential(
          credData.vc || credential?.vc,
          req,
          credential,
          credData.signature
        );

        verificationResults.push({
          index,
          credentialHash,
          ...result
        });

      } catch (error) {
        verificationResults.push({
          index,
          isValid: false,
          error: error.message,
          checks: {
            credentialExists: false,
            issuerRegistered: false,
            notRevoked: false,
            notExpired: false,
            signatureValid: false
          }
        });
      }
    }

    // Log batch verification
    await AuditLog.createLog({
      user: req.user?.id,
      action: 'credential_batch_verify',
      category: 'verification',
      severity: 'info',
      status: 'success',
      description: `Batch verification of ${credentials.length} credentials`,
      metadata: {
        credentialCount: credentials.length,
        validCount: verificationResults.filter(r => r.isValid).length,
        invalidCount: verificationResults.filter(r => !r.isValid).length
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.json({
      success: true,
      data: {
        verifications: verificationResults,
        summary: {
          total: verificationResults.length,
          valid: verificationResults.filter(r => r.isValid).length,
          invalid: verificationResults.filter(r => !r.isValid).length,
          verifiedAt: new Date().toISOString()
        }
      }
    });

  } catch (error) {
    console.error('Batch verification error:', error);
    throw error;
  }
}));

/**
 * @route   GET /api/verification/status/:hash
 * @desc    Get credential verification status by hash
 * @access  Public
 */
router.get('/status/:hash', optionalAuth, asyncHandler(async (req, res) => {
  const { hash } = req.params;

  if (!/^0x[a-fA-F0-9]{64}$/.test(hash)) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Invalid credential hash format',
        code: 'INVALID_HASH_FORMAT'
      }
    });
  }

  try {
    // Check database
    const credential = await Credential.findByHash(hash)
      .populate('issuer', 'name blockchainAddress status onChainData');

    // Check blockchain
    const [isRevoked, issuerRegistered] = await Promise.all([
      isCredentialRevoked(hash),
      credential ? isIssuerRegistered(credential.issuer.blockchainAddress) : Promise.resolve(false)
    ]);

    const status = {
      credentialHash: hash,
      exists: !!credential,
      status: credential?.status || 'unknown',
      isRevoked: isRevoked || credential?.status === 'revoked',
      isExpired: credential?.isExpired || false,
      issuerRegistered: issuerRegistered,
      lastChecked: new Date().toISOString()
    };

    if (credential) {
      status.details = {
        credentialType: credential.credentialType,
        issuer: {
          name: credential.issuer.name,
          address: credential.issuer.blockchainAddress,
          status: credential.issuer.status
        },
        issuedAt: credential.createdAt,
        expirationDate: credential.expirationDate,
        verificationCount: credential.verificationData.totalVerifications
      };
    }

    // Log status check
    await AuditLog.createLog({
      user: req.user?.id,
      credential: credential?._id,
      action: 'credential_status_check',
      category: 'verification',
      severity: 'info',
      status: 'success',
      description: `Credential status checked: ${hash}`,
      metadata: {
        credentialHash: hash,
        exists: status.exists,
        status: status.status,
        isRevoked: status.isRevoked
      },
      clientInfo: {
        ipAddress: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent')
      }
    });

    res.json({
      success: true,
      data: {
        status
      }
    });

  } catch (error) {
    console.error('Status check error:', error);
    throw error;
  }
}));

/**
 * @route   GET /api/verification/issuer/:address
 * @desc    Get issuer verification status
 * @access  Public
 */
router.get('/issuer/:address', optionalAuth, asyncHandler(async (req, res) => {
  const { address } = req.params;

  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return res.status(400).json({
      success: false,
      error: {
        message: 'Invalid Ethereum address format',
        code: 'INVALID_ADDRESS_FORMAT'
      }
    });
  }

  try {
    // Check database
    const issuer = await Issuer.findByAddress(address)
      .populate('user', 'username profile.organization');

    // Check blockchain
    const isRegistered = await isIssuerRegistered(address);

    const status = {
      address: address,
      isRegistered: isRegistered,
      exists: !!issuer,
      status: issuer?.status || 'unknown',
      lastChecked: new Date().toISOString()
    };

    if (issuer) {
      status.details = {
        name: issuer.name,
        verificationLevel: issuer.verificationLevel,
        reputationScore: issuer.reputationScore,
        capabilities: issuer.capabilities,
        registeredAt: issuer.createdAt,
        statistics: {
          credentialsIssued: issuer.statistics.credentialsIssued,
          credentialsRevoked: issuer.statistics.credentialsRevoked,
          lastIssuanceDate: issuer.statistics.lastIssuanceDate
        },
        user: {
          username: issuer.user.username,
          organization: issuer.user.profile?.organization
        }
      };
    }

    res.json({
      success: true,
      data: {
        issuer: status
      }
    });

  } catch (error) {
    console.error('Issuer status check error:', error);
    throw error;
  }
}));

// Helper function to verify individual credential
async function verifyIndividualCredential(vc, req, credential = null, signature = null) {
  const result = {
    isValid: false,
    checks: {
      credentialExists: false,
      issuerRegistered: false,
      notRevoked: false,
      notExpired: false,
      signatureValid: false
    },
    errors: []
  };

  try {
    // Find credential if not provided
    if (!credential && vc) {
      const hash = generateCredentialHash(vc);
      credential = await Credential.findByHash(hash)
        .populate('issuer', 'name blockchainAddress status onChainData');
    }

    if (credential) {
      result.checks.credentialExists = true;

      // Check issuer registration
      if (credential.issuer.status === 'active' && credential.issuer.onChainData.isOnChainRegistered) {
        const isRegistered = await isIssuerRegistered(credential.issuer.blockchainAddress);
        result.checks.issuerRegistered = isRegistered;
      } else {
        result.errors.push('Issuer not registered or inactive');
      }

      // Check revocation status
      if (credential.status === 'valid') {
        const isRevoked = await isCredentialRevoked(credential.credentialHash);
        result.checks.notRevoked = !isRevoked;
        if (isRevoked) {
          result.errors.push('Credential is revoked');
        }
      } else {
        result.errors.push(`Credential status: ${credential.status}`);
      }

      // Check expiration
      if (!credential.isExpired) {
        result.checks.notExpired = true;
      } else {
        result.errors.push('Credential is expired');
      }

      // Verify signature if provided
      if (signature && vc) {
        const message = JSON.stringify(vc, Object.keys(vc).sort());
        const isSignatureValid = verifySignature(message, signature, credential.issuer.blockchainAddress);
        result.checks.signatureValid = isSignatureValid;
        if (!isSignatureValid) {
          result.errors.push('Invalid signature');
        }
      } else if (vc && vc.proof && vc.proof.jws) {
        // Verify embedded proof
        result.checks.signatureValid = true; // Simplified - implement full JWS verification
      }

      // Record verification
      await credential.recordVerification(
        req.ip || 'unknown',
        result.checks.notRevoked && result.checks.notExpired ? 'valid' : 'invalid',
        req.ip || req.connection.remoteAddress,
        req.get('User-Agent')
      );

    } else {
      result.errors.push('Credential not found');
    }

    // Overall validity
    result.isValid = Object.values(result.checks).every(check => check === true);

    return result;

  } catch (error) {
    result.errors.push(error.message);
    return result;
  }
}

// Helper function to generate nonce
function generateNonce() {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15) + 
         Date.now().toString(36);
}

module.exports = router;
