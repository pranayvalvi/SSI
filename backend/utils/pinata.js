const axios = require('axios');

// Pinata API configuration
const PINATA_API_URL = 'https://api.pinata.cloud';
const PINATA_GATEWAY = process.env.PINATA_GATEWAY || 'gateway.pinata.cloud';

/**
 * Test Pinata connection
 */
async function testPinataConnection() {
  try {
    const response = await axios.get(`${PINATA_API_URL}/data/testAuthentication`, {
      headers: {
        'Authorization': `Bearer ${process.env.PINATA_JWT}`
      }
    });
    
    console.log('✅ Pinata connection successful:', response.data);
    return true;
  } catch (error) {
    console.error('❌ Pinata connection failed:', error.message);
    return false;
  }
}

/**
 * Pin JSON data to IPFS via Pinata
 */
async function pinJsonToIPFS(jsonData, options = {}) {
  try {
    if (!jsonData || typeof jsonData !== 'object') {
      throw new Error('Invalid JSON data provided');
    }

    const data = {
      pinataContent: jsonData,
      pinataMetadata: {
        name: options.name || `SSI-Data-${Date.now()}`,
        keyvalues: {
          type: options.type || 'credential-data',
          timestamp: new Date().toISOString(),
          version: '1.0',
          ...options.metadata
        }
      },
      pinataOptions: {
        cidVersion: 1,
        ...options.pinataOptions
      }
    };

    const response = await axios.post(`${PINATA_API_URL}/pinning/pinJSONToIPFS`, data, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.PINATA_JWT}`
      }
    });
    
    console.log(`📌 JSON pinned to IPFS: ${response.data.IpfsHash}`);
    
    return {
      ipfsHash: response.data.IpfsHash,
      pinSize: response.data.PinSize,
      timestamp: response.data.Timestamp,
      isDuplicate: response.data.isDuplicate || false
    };
  } catch (error) {
    console.error('❌ Failed to pin JSON to IPFS:', error);
    throw new Error(`IPFS pinning failed: ${error.response?.data?.error || error.message}`);
  }
}

/**
 * Pin file to IPFS via Pinata
 */
async function pinFileToIPFS(fileBuffer, options = {}) {
  try {
    const FormData = require('form-data');
    const formData = new FormData();
    
    formData.append('file', fileBuffer, options.filename || 'file');
    
    const metadata = {
      name: options.name || `SSI-File-${Date.now()}`,
      keyvalues: {
        type: options.type || 'file',
        timestamp: new Date().toISOString(),
        ...options.metadata
      }
    };
    
    formData.append('pinataMetadata', JSON.stringify(metadata));
    
    if (options.pinataOptions) {
      formData.append('pinataOptions', JSON.stringify(options.pinataOptions));
    }

    const response = await axios.post(`${PINATA_API_URL}/pinning/pinFileToIPFS`, formData, {
      headers: {
        ...formData.getHeaders(),
        'Authorization': `Bearer ${process.env.PINATA_JWT}`
      }
    });
    
    console.log(`📌 File pinned to IPFS: ${response.data.IpfsHash}`);
    
    return {
      ipfsHash: response.data.IpfsHash,
      pinSize: response.data.PinSize,
      timestamp: response.data.Timestamp,
      isDuplicate: response.data.isDuplicate || false
    };
  } catch (error) {
    console.error('❌ Failed to pin file to IPFS:', error);
    throw new Error(`IPFS file pinning failed: ${error.response?.data?.error || error.message}`);
  }
}

/**
 * Retrieve data from IPFS
 */
async function getFromIPFS(ipfsHash, options = {}) {
  try {
    if (!ipfsHash) {
      throw new Error('IPFS hash is required');
    }

    // Clean hash (remove ipfs:// prefix if present)
    const cleanHash = ipfsHash.replace('ipfs://', '');
    
    // Try multiple gateways for reliability
    const gateways = [
      `https://${PINATA_GATEWAY}/ipfs/${cleanHash}`,
      `https://ipfs.io/ipfs/${cleanHash}`,
      `https://cloudflare-ipfs.com/ipfs/${cleanHash}`,
      `https://dweb.link/ipfs/${cleanHash}`
    ];

    let lastError;
    
    for (const gateway of gateways) {
      try {
        const response = await axios.get(gateway, {
          timeout: options.timeout || 10000,
          headers: {
            'Accept': 'application/json, text/plain, */*'
          }
        });
        
        console.log(`📥 Retrieved data from IPFS: ${cleanHash}`);
        return response.data;
      } catch (error) {
        lastError = error;
        console.warn(`⚠️ Gateway failed: ${gateway}`, error.message);
        continue;
      }
    }
    
    throw lastError || new Error('All IPFS gateways failed');
  } catch (error) {
    console.error('❌ Failed to retrieve from IPFS:', error);
    throw new Error(`IPFS retrieval failed: ${error.message}`);
  }
}

/**
 * Unpin data from Pinata (cleanup)
 */
async function unpinFromIPFS(ipfsHash) {
  try {
    if (!ipfsHash) {
      throw new Error('IPFS hash is required');
    }

    const cleanHash = ipfsHash.replace('ipfs://', '');
    
    const response = await axios.delete(`${PINATA_API_URL}/pinning/unpin/${cleanHash}`, {
      headers: {
        'Authorization': `Bearer ${process.env.PINATA_JWT}`
      }
    });
    
    console.log(`🗑️ Unpinned from IPFS: ${cleanHash}`);
    return response.data;
  } catch (error) {
    console.error('❌ Failed to unpin from IPFS:', error);
    throw new Error(`IPFS unpinning failed: ${error.response?.data?.error || error.message}`);
  }
}

/**
 * List pinned files
 */
async function listPinnedFiles(options = {}) {
  try {
    const params = {
      status: 'pinned',
      pageLimit: options.limit || 100,
      pageOffset: options.offset || 0,
      ...options.filters
    };

    const response = await axios.get(`${PINATA_API_URL}/data/pinList`, {
      params,
      headers: {
        'Authorization': `Bearer ${process.env.PINATA_JWT}`
      }
    });
    
    return {
      pins: response.data.rows,
      count: response.data.count,
      totalSize: response.data.rows.reduce((sum, pin) => sum + parseInt(pin.size), 0)
    };
  } catch (error) {
    console.error('❌ Failed to list pinned files:', error);
    throw new Error(`Failed to list pins: ${error.response?.data?.error || error.message}`);
  }
}

/**
 * Pin issuer metadata to IPFS
 */
async function pinIssuerMetadata(issuerData) {
  try {
    const metadata = {
      type: 'issuer',
      name: issuerData.name,
      description: issuerData.description,
      website: issuerData.website,
      logo: issuerData.logo,
      contactInfo: issuerData.contactInfo,
      capabilities: issuerData.capabilities,
      verificationLevel: issuerData.verificationLevel,
      createdAt: new Date().toISOString(),
      version: '1.0'
    };

    return await pinJsonToIPFS(metadata, {
      name: `Issuer-${issuerData.name}-${Date.now()}`,
      type: 'issuer-metadata',
      metadata: {
        issuerName: issuerData.name,
        walletAddress: issuerData.blockchainAddress
      }
    });
  } catch (error) {
    throw new Error(`Failed to pin issuer metadata: ${error.message}`);
  }
}

/**
 * Pin credential metadata to IPFS
 */
async function pinCredentialMetadata(credentialData) {
  try {
    const metadata = {
      type: 'credential',
      credential: credentialData.vc,
      issuer: credentialData.issuerMetadataUri,
      subject: credentialData.subject,
      issuedAt: new Date().toISOString(),
      credentialHash: credentialData.credentialHash,
      version: '1.0'
    };

    return await pinJsonToIPFS(metadata, {
      name: `Credential-${credentialData.credentialHash.slice(0, 10)}-${Date.now()}`,
      type: 'credential-metadata',
      metadata: {
        credentialType: credentialData.vc.type,
        issuer: credentialData.vc.issuer,
        subject: credentialData.subject
      }
    });
  } catch (error) {
    throw new Error(`Failed to pin credential metadata: ${error.message}`);
  }
}

/**
 * Validate IPFS hash format
 */
function validateIPFSHash(hash) {
  if (!hash) return false;
  
  const cleanHash = hash.replace('ipfs://', '');
  
  // Check for CIDv0 (Qm...)
  if (/^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(cleanHash)) {
    return true;
  }
  
  // Check for CIDv1 (baf...)
  if (/^baf[a-z0-9]{56}$/.test(cleanHash)) {
    return true;
  }
  
  return false;
}

/**
 * Generate IPFS URI from hash
 */
function generateIPFSUri(hash) {
  const cleanHash = hash.replace('ipfs://', '');
  return `ipfs://${cleanHash}`;
}

/**
 * Get IPFS gateway URL
 */
function getGatewayUrl(hash, gateway = 'pinata') {
  const cleanHash = hash.replace('ipfs://', '');
  
  const gateways = {
    pinata: `https://${PINATA_GATEWAY}/ipfs/${cleanHash}`,
    ipfs: `https://ipfs.io/ipfs/${cleanHash}`,
    cloudflare: `https://cloudflare-ipfs.com/ipfs/${cleanHash}`,
    dweb: `https://dweb.link/ipfs/${cleanHash}`
  };
  
  return gateways[gateway] || gateways.pinata;
}

module.exports = {
  testPinataConnection,
  pinJsonToIPFS,
  pinFileToIPFS,
  getFromIPFS,
  unpinFromIPFS,
  listPinnedFiles,
  pinIssuerMetadata,
  pinCredentialMetadata,
  validateIPFSHash,
  generateIPFSUri,
  getGatewayUrl
};