import { 
  ethers, 
  isAddress, 
  formatEther, 
  parseEther, 
  keccak256, 
  toUtf8Bytes, 
  verifyMessage, 
  verifyTypedData,
  formatUnits
} from 'ethers';

// Detect Ethereum provider (MetaMask, etc.)
export const detectEthereumProvider = async () => {
  if (typeof window === 'undefined') {
    return null;
  }

  // Check for MetaMask
  if (window.ethereum) {
    return window.ethereum;
  }

  // Check for legacy web3
  if (window.web3 && window.web3.currentProvider) {
    return window.web3.currentProvider;
  }

  return null;
};

// Check if MetaMask is installed
export const isMetaMaskInstalled = () => {
  return typeof window !== 'undefined' && Boolean(window.ethereum && window.ethereum.isMetaMask);
};

// Format Ethereum address for display
export const formatAddress = (address, length = 4) => {
  if (!address) return '';
  if (address.length <= length * 2 + 2) return address;
  
  return `${address.slice(0, length + 2)}...${address.slice(-length)}`;
};

// Validate Ethereum address
export const isValidAddress = (address) => {
  try {
    return isAddress(address);
  } catch (error) {
    return false;
  }
};

// Format Wei to Ether
export const formatEtherValue = (wei, decimals = 4) => {
  try {
    const ether = formatEther(wei);
    return parseFloat(ether).toFixed(decimals);
  } catch (error) {
    return '0';
  }
};

// Parse Ether to Wei
export const parseEtherValue = (ether) => {
  try {
    return parseEther(ether.toString());
  } catch (error) {
    return BigInt(0);
  }
};

// Generate credential hash (keccak256)
export const generateCredentialHash = (credentialData) => {
  try {
    const credentialString = JSON.stringify(credentialData, Object.keys(credentialData).sort());
    return keccak256(toUtf8Bytes(credentialString));
  } catch (error) {
    console.error('Failed to generate credential hash:', error);
    throw new Error('Hash generation failed');
  }
};

// Sign message with MetaMask
export const signMessage = async (signer, message) => {
  try {
    const signature = await signer.signMessage(message);
    return { success: true, signature };
  } catch (error) {
    console.error('Message signing failed:', error);
    
    let errorMessage = 'Failed to sign message';
    if (error.code === 4001) {
      errorMessage = 'Signature rejected by user';
    }
    
    return { success: false, error: errorMessage };
  }
};

// Sign typed data (EIP-712)
export const signTypedData = async (signer, domain, types, value) => {
  try {
    const signature = await signer._signTypedData(domain, types, value);
    return { success: true, signature };
  } catch (error) {
    console.error('Typed data signing failed:', error);
    
    let errorMessage = 'Failed to sign typed data';
    if (error.code === 4001) {
      errorMessage = 'Signature rejected by user';
    }
    
    return { success: false, error: errorMessage };
  }
};

// Verify message signature
export const verifyMessageSignature = (message, signature, expectedSigner) => {
  try {
    const recoveredAddress = verifyMessage(message, signature);
    return recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
  } catch (error) {
    console.error('Message verification failed:', error);
    return false;
  }
};

// Verify typed data signature
export const verifyTypedDataSignature = (domain, types, value, signature, expectedSigner) => {
  try {
    const recoveredAddress = verifyTypedData(domain, types, value, signature);
    return recoveredAddress.toLowerCase() === expectedSigner.toLowerCase();
  } catch (error) {
    console.error('Typed data verification failed:', error);
    return false;
  }
};

// Get network information
export const getNetworkInfo = (chainId) => {
  const networks = {
    1: { name: 'Ethereum Mainnet', symbol: 'ETH', explorer: 'https://etherscan.io' },
    5: { name: 'Goerli Testnet', symbol: 'ETH', explorer: 'https://goerli.etherscan.io' },
    11155111: { name: 'Sepolia Testnet', symbol: 'SEP', explorer: 'https://sepolia.etherscan.io' },
    137: { name: 'Polygon Mainnet', symbol: 'MATIC', explorer: 'https://polygonscan.com' },
    80001: { name: 'Mumbai Testnet', symbol: 'MATIC', explorer: 'https://mumbai.polygonscan.com' },
  };
  
  return networks[chainId] || { name: 'Unknown Network', symbol: 'ETH', explorer: '' };
};

// Get transaction URL
export const getTransactionUrl = (txHash, chainId = 11155111) => {
  const network = getNetworkInfo(chainId);
  return `${network.explorer}/tx/${txHash}`;
};

// Get address URL
export const getAddressUrl = (address, chainId = 11155111) => {
  const network = getNetworkInfo(chainId);
  return `${network.explorer}/address/${address}`;
};

// Wait for transaction with timeout
export const waitForTransaction = async (provider, txHash, confirmations = 1, timeout = 300000) => {
  try {
    const receipt = await Promise.race([
      provider.waitForTransaction(txHash, confirmations),
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Transaction timeout')), timeout)
      )
    ]);
    
    return { success: true, receipt };
  } catch (error) {
    console.error('Transaction wait failed:', error);
    return { success: false, error: error.message };
  }
};

// Estimate gas with buffer
export const estimateGasWithBuffer = async (contract, method, args = [], bufferPercent = 20) => {
  try {
    const gasEstimate = await contract.estimateGas[method](...args);
    const buffer = gasEstimate.mul(bufferPercent).div(100);
    return gasEstimate.add(buffer);
  } catch (error) {
    console.error('Gas estimation failed:', error);
    throw error;
  }
};

// Get current gas price
export const getCurrentGasPrice = async (provider) => {
  try {
    const gasPrice = await provider.getGasPrice();
    return gasPrice;
  } catch (error) {
    console.error('Failed to get gas price:', error);
    return null;
  }
};

// Format gas price for display
export const formatGasPrice = (gasPrice) => {
  try {
    const gwei = formatUnits(gasPrice, 'gwei');
    return `${parseFloat(gwei).toFixed(2)} Gwei`;
  } catch (error) {
    return 'Unknown';
  }
};

// Create EIP-712 domain
export const createEIP712Domain = (name, version, chainId, verifyingContract) => {
  return {
    name,
    version,
    chainId,
    verifyingContract
  };
};

// Create credential signature types for EIP-712
export const getCredentialSignatureTypes = () => {
  return {
    VerifiableCredential: [
      { name: 'context', type: 'string[]' },
      { name: 'id', type: 'string' },
      { name: 'type', type: 'string[]' },
      { name: 'issuer', type: 'string' },
      { name: 'issuanceDate', type: 'string' },
      { name: 'credentialSubject', type: 'string' }, // JSON string
    ]
  };
};

// Create presentation signature types for EIP-712
export const getPresentationSignatureTypes = () => {
  return {
    VerifiablePresentation: [
      { name: 'context', type: 'string[]' },
      { name: 'type', type: 'string[]' },
      { name: 'verifiableCredential', type: 'string[]' }, // Array of credential hashes
      { name: 'holder', type: 'address' },
      { name: 'challenge', type: 'string' },
      { name: 'domain', type: 'string' },
    ]
  };
};

// Switch network helper
export const switchNetwork = async (chainId) => {
  try {
    const ethereum = await detectEthereumProvider();
    if (!ethereum) {
      throw new Error('No Ethereum provider found');
    }

    await ethereum.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: `0x${chainId.toString(16)}` }],
    });
    
    return { success: true };
  } catch (error) {
    console.error('Network switch failed:', error);
    return { success: false, error: error.message };
  }
};

// Add network helper
export const addNetwork = async (networkConfig) => {
  try {
    const ethereum = await detectEthereumProvider();
    if (!ethereum) {
      throw new Error('No Ethereum provider found');
    }

    await ethereum.request({
      method: 'wallet_addEthereumChain',
      params: [networkConfig],
    });
    
    return { success: true };
  } catch (error) {
    console.error('Network addition failed:', error);
    return { success: false, error: error.message };
  }
};

// Get Sepolia network config
export const getSepoliaNetworkConfig = () => {
  return {
    chainId: '0xaa36a7', // 11155111 in hex
    chainName: 'Sepolia Testnet',
    nativeCurrency: {
      name: 'Sepolia ETH',
      symbol: 'SEP',
      decimals: 18,
    },
    rpcUrls: [
      process.env.REACT_APP_SEPOLIA_RPC || 'https://rpc.sepolia.org'
    ],
    blockExplorerUrls: ['https://sepolia.etherscan.io'],
  };
};

// Check if browser supports Web3
export const isWeb3Supported = () => {
  return typeof window !== 'undefined' && (
    typeof window.ethereum !== 'undefined' ||
    typeof window.web3 !== 'undefined'
  );
};

// Get Web3 provider info
export const getProviderInfo = async () => {
  const ethereum = await detectEthereumProvider();
  if (!ethereum) {
    return { supported: false };
  }

  return {
    supported: true,
    isMetaMask: ethereum.isMetaMask || false,
    chainId: ethereum.chainId,
    networkVersion: ethereum.networkVersion,
    selectedAddress: ethereum.selectedAddress,
  };
};

export default {
  detectEthereumProvider,
  isMetaMaskInstalled,
  formatAddress,
  isValidAddress,
  formatEther: formatEtherValue,
  parseEther: parseEtherValue,
  generateCredentialHash,
  signMessage,
  signTypedData,
  verifyMessage: verifyMessageSignature,
  verifyTypedData: verifyTypedDataSignature,
  getNetworkInfo,
  getTransactionUrl,
  getAddressUrl,
  waitForTransaction,
  estimateGasWithBuffer,
  getCurrentGasPrice,
  formatGasPrice,
  createEIP712Domain,
  getCredentialSignatureTypes,
  getPresentationSignatureTypes,
  switchNetwork,
  addNetwork,
  getSepoliaNetworkConfig,
  isWeb3Supported,
  getProviderInfo,
};
