const { ethers, isAddress, keccak256, toUtf8Bytes, verifyMessage, verifyTypedData } = require('ethers');

// Contract ABI for IssuerRegistry
const CONTRACT_ABI = [
  "function registerIssuer(address issuerAddr, string calldata metadataUri) external",
  "function updateIssuer(address issuerAddr, string calldata metadataUri) external",
  "function setIssuerStatus(address issuerAddr, bool isActive) external",
  "function revokeCredential(bytes32 credentialHash) external",
  "function batchRevokeCredentials(bytes32[] calldata credentialHashes) external",
  "function isIssuerRegistered(address issuerAddr) external view returns (bool)",
  "function isCredentialRevoked(bytes32 credentialHash) external view returns (bool)",
  "function getIssuerMetadata(address issuerAddr) external view returns (string memory)",
  "function getIssuer(address issuerAddr) external view returns (tuple(address addr, string metadataUri, uint256 registeredAt, bool exists, bool isActive))",
  "function getIssuerCount() external view returns (uint256)",
  "function getIssuerByIndex(uint256 index) external view returns (address)",
  "function owner() external view returns (address)",
  "event IssuerRegistered(address indexed issuer, string metadataUri, uint256 timestamp)",
  "event IssuerUpdated(address indexed issuer, string metadataUri, uint256 timestamp)",
  "event IssuerStatusChanged(address indexed issuer, bool isActive, uint256 timestamp)",
  "event CredentialRevoked(bytes32 indexed credentialHash, address indexed revokedBy, uint256 timestamp)"
];

/**
 * Get blockchain provider
 */
function getProvider() {
  const rpcUrl = process.env.SEPOLIA_RPC || 'https://rpc.sepolia.org';
  return new ethers.JsonRpcProvider(rpcUrl);
}

/**
 * Get contract instance
 */
function getContract(signerOrProvider = null) {
  const contractAddress = process.env.CONTRACT_ADDRESS;
  
  if (!contractAddress) {
    throw new Error('CONTRACT_ADDRESS not configured');
  }
  
  const provider = signerOrProvider || getProvider();
  return new ethers.Contract(contractAddress, CONTRACT_ABI, provider);
}

/**
 * Check if issuer is registered on-chain
 */
async function isIssuerRegistered(issuerAddress) {
  try {
    const contract = getContract();
    const isRegistered = await contract.isIssuerRegistered(issuerAddress);
    
    console.log(`🔍 Issuer ${issuerAddress} registration status: ${isRegistered}`);
    return isRegistered;
  } catch (error) {
    console.error('❌ Failed to check issuer registration:', error);
    throw new Error(`Blockchain query failed: ${error.message}`);
  }
}

/**
 * Check if credential is revoked on-chain
 */
async function isCredentialRevoked(credentialHash) {
  try {
    const contract = getContract();
    const isRevoked = await contract.isCredentialRevoked(credentialHash);
    
    console.log(`🔍 Credential ${credentialHash} revocation status: ${isRevoked}`);
    return isRevoked;
  } catch (error) {
    console.error('❌ Failed to check credential revocation:', error);
    throw new Error(`Blockchain query failed: ${error.message}`);
  }
}

/**
 * Get issuer metadata URI from blockchain
 */
async function getIssuerMetadata(issuerAddress) {
  try {
    const contract = getContract();
    const metadataUri = await contract.getIssuerMetadata(issuerAddress);
    
    console.log(`📄 Issuer ${issuerAddress} metadata URI: ${metadataUri}`);
    return metadataUri;
  } catch (error) {
    console.error('❌ Failed to get issuer metadata:', error);
    throw new Error(`Blockchain query failed: ${error.message}`);
  }
}

/**
 * Get complete issuer information from blockchain
 */
async function getIssuerInfo(issuerAddress) {
  try {
    const contract = getContract();
    const issuerInfo = await contract.getIssuer(issuerAddress);
    
    const result = {
      address: issuerInfo.addr,
      metadataUri: issuerInfo.metadataUri,
      registeredAt: new Date(Number(issuerInfo.registeredAt) * 1000),
      exists: issuerInfo.exists,
      isActive: issuerInfo.isActive
    };
    
    console.log(`📋 Issuer info for ${issuerAddress}:`, result);
    return result;
  } catch (error) {
    console.error('❌ Failed to get issuer info:', error);
    throw new Error(`Blockchain query failed: ${error.message}`);
  }
}

/**
 * Get total number of registered issuers
 */
async function getIssuerCount() {
  try {
    const contract = getContract();
    const count = await contract.getIssuerCount();
    
    console.log(`📊 Total registered issuers: ${Number(count)}`);
    return Number(count);
  } catch (error) {
    console.error('❌ Failed to get issuer count:', error);
    throw new Error(`Blockchain query failed: ${error.message}`);
  }
}

/**
 * Get issuer address by index
 */
async function getIssuerByIndex(index) {
  try {
    const contract = getContract();
    const issuerAddress = await contract.getIssuerByIndex(index);
    
    console.log(`📍 Issuer at index ${index}: ${issuerAddress}`);
    return issuerAddress;
  } catch (error) {
    console.error('❌ Failed to get issuer by index:', error);
    throw new Error(`Blockchain query failed: ${error.message}`);
  }
}

/**
 * Get all registered issuers
 */
async function getAllIssuers() {
  try {
    const count = await getIssuerCount();
    const issuers = [];
    
    for (let i = 0; i < count; i++) {
      try {
        const address = await getIssuerByIndex(i);
        const info = await getIssuerInfo(address);
        issuers.push(info);
      } catch (error) {
        console.warn(`⚠️ Failed to get issuer at index ${i}:`, error.message);
      }
    }
    
    console.log(`📋 Retrieved ${issuers.length} issuers from blockchain`);
    return issuers;
  } catch (error) {
    console.error('❌ Failed to get all issuers:', error);
    throw new Error(`Failed to retrieve issuers: ${error.message}`);
  }
}

/**
 * Validate Ethereum address format
 */
function isValidAddress(address) {
  try {
    // Convert to lowercase for validation to avoid checksum issues
    const lowerAddress = address.toLowerCase();
    return isAddress(lowerAddress);
  } catch (error) {
    return false;
  }
}

/**
 * Generate credential hash for blockchain operations
 */
function generateCredentialHash(credentialData) {
  try {
    // Create a deterministic hash of the credential
    const credentialString = JSON.stringify(credentialData, Object.keys(credentialData).sort());
    const hash = keccak256(toUtf8Bytes(credentialString));
    
    console.log(`🔐 Generated credential hash: ${hash}`);
    return hash;
  } catch (error) {
    console.error('❌ Failed to generate credential hash:', error);
    throw new Error(`Hash generation failed: ${error.message}`);
  }
}

/**
 * Verify message signature
 */
function verifySignature(message, signature, expectedSigner) {
  try {
    const recoveredAddress = verifyMessage(message, signature);
    const isValid = recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
    
    console.log(`🔐 Signature verification: ${isValid ? 'VALID' : 'INVALID'}`);
    console.log(`   Expected: ${expectedSigner}`);
    console.log(`   Recovered: ${recoveredAddress}`);
    
    return isValid;
  } catch (error) {
    console.error('❌ Signature verification failed:', error);
    return false;
  }
}

/**
 * Verify typed data signature (EIP-712)
 */
function verifyTypedDataSignature(domain, types, value, signature, expectedSigner) {
  try {
    const recoveredAddress = verifyTypedData(domain, types, value, signature);
    const isValid = recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
    
    console.log(`🔐 Typed data signature verification: ${isValid ? 'VALID' : 'INVALID'}`);
    console.log(`   Expected: ${expectedSigner}`);
    console.log(`   Recovered: ${recoveredAddress}`);
    
    return isValid;
  } catch (error) {
    console.error('❌ Typed data signature verification failed:', error);
    return false;
  }
}

/**
 * Get transaction receipt and details
 */
async function getTransactionDetails(txHash) {
  try {
    const provider = getProvider();
    
    // Get transaction and receipt
    const [tx, receipt] = await Promise.all([
      provider.getTransaction(txHash),
      provider.getTransactionReceipt(txHash)
    ]);
    
    if (!tx || !receipt) {
      throw new Error('Transaction not found');
    }
    
    const result = {
      hash: tx.hash,
      blockNumber: receipt.blockNumber,
      blockHash: receipt.blockHash,
      from: tx.from,
      to: tx.to,
      gasUsed: receipt.gasUsed.toString(),
      gasPrice: tx.gasPrice.toString(),
      status: receipt.status,
      timestamp: null,
      logs: receipt.logs
    };
    
    // Get block timestamp
    if (receipt.blockNumber) {
      const block = await provider.getBlock(receipt.blockNumber);
      result.timestamp = new Date(block.timestamp * 1000);
    }
    
    console.log(`📋 Transaction details for ${txHash}:`, result);
    return result;
  } catch (error) {
    console.error('❌ Failed to get transaction details:', error);
    throw new Error(`Transaction query failed: ${error.message}`);
  }
}

/**
 * Parse contract events from transaction receipt
 */
function parseContractEvents(receipt, eventNames = []) {
  try {
    const contract = getContract();
    const events = [];
    
    for (const log of receipt.logs) {
      try {
        const parsedLog = contract.interface.parseLog(log);
        
        if (eventNames.length === 0 || eventNames.includes(parsedLog.name)) {
          events.push({
            name: parsedLog.name,
            args: parsedLog.args,
            signature: parsedLog.signature,
            topic: parsedLog.topic,
            address: log.address,
            blockNumber: log.blockNumber,
            transactionHash: log.transactionHash,
            logIndex: log.logIndex
          });
        }
      } catch (error) {
        // Log might not be from our contract, skip it
        continue;
      }
    }
    
    console.log(`📋 Parsed ${events.length} contract events`);
    return events;
  } catch (error) {
    console.error('❌ Failed to parse contract events:', error);
    return [];
  }
}

/**
 * Monitor blockchain events
 */
function setupEventListeners(eventHandlers = {}) {
  try {
    const contract = getContract();
    
    // Listen for IssuerRegistered events
    if (eventHandlers.onIssuerRegistered) {
      contract.on('IssuerRegistered', (issuer, metadataUri, timestamp, event) => {
        console.log(`📡 IssuerRegistered event: ${issuer}`);
        eventHandlers.onIssuerRegistered({
          issuer,
          metadataUri,
          timestamp: new Date(timestamp.toNumber() * 1000),
          event
        });
      });
    }
    
    // Listen for CredentialRevoked events
    if (eventHandlers.onCredentialRevoked) {
      contract.on('CredentialRevoked', (credentialHash, revokedBy, timestamp, event) => {
        console.log(`📡 CredentialRevoked event: ${credentialHash}`);
        eventHandlers.onCredentialRevoked({
          credentialHash,
          revokedBy,
          timestamp: new Date(timestamp.toNumber() * 1000),
          event
        });
      });
    }
    
    // Listen for IssuerStatusChanged events
    if (eventHandlers.onIssuerStatusChanged) {
      contract.on('IssuerStatusChanged', (issuer, isActive, timestamp, event) => {
        console.log(`📡 IssuerStatusChanged event: ${issuer} -> ${isActive}`);
        eventHandlers.onIssuerStatusChanged({
          issuer,
          isActive,
          timestamp: new Date(timestamp.toNumber() * 1000),
          event
        });
      });
    }
    
    console.log('📡 Blockchain event listeners setup complete');
    return contract;
  } catch (error) {
    console.error('❌ Failed to setup event listeners:', error);
    throw new Error(`Event listener setup failed: ${error.message}`);
  }
}

/**
 * Get current network information
 */
async function getNetworkInfo() {
  try {
    const provider = getProvider();
    const network = await provider.getNetwork();
    const blockNumber = await provider.getBlockNumber();
    
    const info = {
      name: network.name,
      chainId: network.chainId,
      blockNumber: blockNumber,
      rpcUrl: process.env.SEPOLIA_RPC || 'https://rpc.sepolia.org',
      contractAddress: process.env.CONTRACT_ADDRESS
    };
    
    console.log('🌐 Network info:', info);
    return info;
  } catch (error) {
    console.error('❌ Failed to get network info:', error);
    throw new Error(`Network query failed: ${error.message}`);
  }
}

/**
 * Estimate gas for contract function
 */
async function estimateGas(functionName, args = [], fromAddress = null) {
  try {
    const contract = getContract();
    
    let gasEstimate;
    if (fromAddress) {
      gasEstimate = await contract.estimateGas[functionName](...args, { from: fromAddress });
    } else {
      gasEstimate = await contract.estimateGas[functionName](...args);
    }
    
    console.log(`⛽ Gas estimate for ${functionName}: ${gasEstimate.toString()}`);
    return gasEstimate.toString();
  } catch (error) {
    console.error('❌ Gas estimation failed:', error);
    throw new Error(`Gas estimation failed: ${error.message}`);
  }
}

module.exports = {
  getProvider,
  getContract,
  isIssuerRegistered,
  isCredentialRevoked,
  getIssuerMetadata,
  getIssuerInfo,
  getIssuerCount,
  getIssuerByIndex,
  getAllIssuers,
  isValidAddress,
  generateCredentialHash,
  verifySignature,
  verifyTypedDataSignature,
  getTransactionDetails,
  parseContractEvents,
  setupEventListeners,
  getNetworkInfo,
  estimateGas,
  CONTRACT_ABI
};
