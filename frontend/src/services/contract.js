import { ethers } from 'ethers';

// Contract ABI - matches the deployed IssuerRegistry contract
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

const CONTRACT_ADDRESS = process.env.REACT_APP_CONTRACT_ADDRESS;

class ContractService {
  constructor() {
    this.contractAddress = CONTRACT_ADDRESS;
    this.abi = CONTRACT_ABI;
  }

  // Get contract instance
  getContract(signerOrProvider) {
    if (!this.contractAddress) {
      throw new Error('Contract address not configured');
    }
    
    return new ethers.Contract(this.contractAddress, this.abi, signerOrProvider);
  }

  // Register issuer on-chain
  async registerIssuer(signer, issuerAddress, metadataUri) {
    try {
      const contract = this.getContract(signer);
      
      // Estimate gas
      const gasEstimate = await contract.estimateGas.registerIssuer(issuerAddress, metadataUri);
      const gasLimit = gasEstimate.mul(120).div(100); // Add 20% buffer
      
      // Send transaction
      const tx = await contract.registerIssuer(issuerAddress, metadataUri, {
        gasLimit: gasLimit
      });
      
      return {
        success: true,
        txHash: tx.hash,
        tx: tx
      };
    } catch (error) {
      console.error('Register issuer error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Update issuer metadata on-chain
  async updateIssuer(signer, issuerAddress, metadataUri) {
    try {
      const contract = this.getContract(signer);
      
      const gasEstimate = await contract.estimateGas.updateIssuer(issuerAddress, metadataUri);
      const gasLimit = gasEstimate.mul(120).div(100);
      
      const tx = await contract.updateIssuer(issuerAddress, metadataUri, {
        gasLimit: gasLimit
      });
      
      return {
        success: true,
        txHash: tx.hash,
        tx: tx
      };
    } catch (error) {
      console.error('Update issuer error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Revoke credential on-chain
  async revokeCredential(signer, credentialHash) {
    try {
      const contract = this.getContract(signer);
      
      const gasEstimate = await contract.estimateGas.revokeCredential(credentialHash);
      const gasLimit = gasEstimate.mul(120).div(100);
      
      const tx = await contract.revokeCredential(credentialHash, {
        gasLimit: gasLimit
      });
      
      return {
        success: true,
        txHash: tx.hash,
        tx: tx
      };
    } catch (error) {
      console.error('Revoke credential error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Batch revoke credentials
  async batchRevokeCredentials(signer, credentialHashes) {
    try {
      const contract = this.getContract(signer);
      
      const gasEstimate = await contract.estimateGas.batchRevokeCredentials(credentialHashes);
      const gasLimit = gasEstimate.mul(120).div(100);
      
      const tx = await contract.batchRevokeCredentials(credentialHashes, {
        gasLimit: gasLimit
      });
      
      return {
        success: true,
        txHash: tx.hash,
        tx: tx
      };
    } catch (error) {
      console.error('Batch revoke credentials error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Check if issuer is registered
  async isIssuerRegistered(provider, issuerAddress) {
    try {
      const contract = this.getContract(provider);
      const isRegistered = await contract.isIssuerRegistered(issuerAddress);
      
      return {
        success: true,
        isRegistered: isRegistered
      };
    } catch (error) {
      console.error('Check issuer registration error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Check if credential is revoked
  async isCredentialRevoked(provider, credentialHash) {
    try {
      const contract = this.getContract(provider);
      const isRevoked = await contract.isCredentialRevoked(credentialHash);
      
      return {
        success: true,
        isRevoked: isRevoked
      };
    } catch (error) {
      console.error('Check credential revocation error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Get issuer metadata URI
  async getIssuerMetadata(provider, issuerAddress) {
    try {
      const contract = this.getContract(provider);
      const metadataUri = await contract.getIssuerMetadata(issuerAddress);
      
      return {
        success: true,
        metadataUri: metadataUri
      };
    } catch (error) {
      console.error('Get issuer metadata error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Get complete issuer information
  async getIssuer(provider, issuerAddress) {
    try {
      const contract = this.getContract(provider);
      const issuerData = await contract.getIssuer(issuerAddress);
      
      return {
        success: true,
        issuer: {
          address: issuerData.addr,
          metadataUri: issuerData.metadataUri,
          registeredAt: new Date(issuerData.registeredAt.toNumber() * 1000),
          exists: issuerData.exists,
          isActive: issuerData.isActive
        }
      };
    } catch (error) {
      console.error('Get issuer error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Get total issuer count
  async getIssuerCount(provider) {
    try {
      const contract = this.getContract(provider);
      const count = await contract.getIssuerCount();
      
      return {
        success: true,
        count: count.toNumber()
      };
    } catch (error) {
      console.error('Get issuer count error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Get issuer by index
  async getIssuerByIndex(provider, index) {
    try {
      const contract = this.getContract(provider);
      const issuerAddress = await contract.getIssuerByIndex(index);
      
      return {
        success: true,
        address: issuerAddress
      };
    } catch (error) {
      console.error('Get issuer by index error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Wait for transaction confirmation
  async waitForTransaction(provider, txHash, confirmations = 1) {
    try {
      const receipt = await provider.waitForTransaction(txHash, confirmations);
      
      return {
        success: true,
        receipt: receipt,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed.toString(),
        status: receipt.status
      };
    } catch (error) {
      console.error('Wait for transaction error:', error);
      return {
        success: false,
        error: this.parseContractError(error)
      };
    }
  }

  // Parse contract events from transaction receipt
  parseEvents(receipt) {
    try {
      const contract = this.getContract();
      const events = [];
      
      for (const log of receipt.logs) {
        try {
          const parsedLog = contract.interface.parseLog(log);
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
        } catch (error) {
          // Log might not be from our contract, skip it
          continue;
        }
      }
      
      return events;
    } catch (error) {
      console.error('Parse events error:', error);
      return [];
    }
  }

  // Set up event listeners
  setupEventListeners(provider, eventHandlers = {}) {
    try {
      const contract = this.getContract(provider);
      
      // Listen for IssuerRegistered events
      if (eventHandlers.onIssuerRegistered) {
        contract.on('IssuerRegistered', (issuer, metadataUri, timestamp, event) => {
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
          eventHandlers.onIssuerStatusChanged({
            issuer,
            isActive,
            timestamp: new Date(timestamp.toNumber() * 1000),
            event
          });
        });
      }
      
      return contract;
    } catch (error) {
      console.error('Setup event listeners error:', error);
      throw error;
    }
  }

  // Parse contract errors into user-friendly messages
  parseContractError(error) {
    let message = 'Transaction failed';
    let code = 'UNKNOWN_ERROR';
    
    if (error.code === 4001) {
      message = 'Transaction rejected by user';
      code = 'USER_REJECTED';
    } else if (error.code === -32603) {
      message = 'Internal JSON-RPC error';
      code = 'RPC_ERROR';
    } else if (error.message) {
      if (error.message.includes('insufficient funds')) {
        message = 'Insufficient funds for gas';
        code = 'INSUFFICIENT_FUNDS';
      } else if (error.message.includes('gas required exceeds allowance')) {
        message = 'Gas limit too low';
        code = 'GAS_LIMIT_TOO_LOW';
      } else if (error.message.includes('nonce too low')) {
        message = 'Nonce too low - please try again';
        code = 'NONCE_TOO_LOW';
      } else if (error.message.includes('replacement transaction underpriced')) {
        message = 'Transaction underpriced - increase gas price';
        code = 'UNDERPRICED';
      } else if (error.reason) {
        message = error.reason;
        code = 'CONTRACT_REVERT';
      } else {
        message = error.message;
      }
    }
    
    return {
      message,
      code,
      originalError: error
    };
  }

  // Get contract info
  getContractInfo() {
    return {
      address: this.contractAddress,
      abi: this.abi,
      network: 'Sepolia Testnet',
      explorerUrl: `https://sepolia.etherscan.io/address/${this.contractAddress}`
    };
  }
}

// Export singleton instance
export const contractService = new ContractService();
export default contractService;
