import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { ethers, BrowserProvider } from 'ethers';
import toast from 'react-hot-toast';
import { contractService } from '../services/contract';
import { detectEthereumProvider } from '../utils/web3';

const Web3Context = createContext({});

export const useWeb3 = () => {
  const context = useContext(Web3Context);
  if (!context) {
    throw new Error('useWeb3 must be used within a Web3Provider');
  }
  return context;
};

export const Web3Provider = ({ children }) => {
  const [provider, setProvider] = useState(null);
  const [signer, setSigner] = useState(null);
  const [account, setAccount] = useState(null);
  const [chainId, setChainId] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [web3Loading, setWeb3Loading] = useState(false);
  const [contract, setContract] = useState(null);

  const SEPOLIA_CHAIN_ID = 11155111;
  const SEPOLIA_RPC = process.env.REACT_APP_SEPOLIA_RPC || 'https://rpc.sepolia.org';

  // Initialize Web3 provider
  const initializeProvider = useCallback(async () => {
    try {
      const ethereum = await detectEthereumProvider();
      if (ethereum) {
        const web3Provider = new BrowserProvider(ethereum);
        setProvider(web3Provider);
        
        // Initialize contract
        const contractInstance = contractService.getContract(web3Provider);
        setContract(contractInstance);
        
        // Check if already connected
        const accounts = await ethereum.request({ method: 'eth_accounts' });
        if (accounts.length > 0) {
          await handleAccountsChanged(accounts);
        }
        
        // Set up event listeners
        ethereum.on('accountsChanged', handleAccountsChanged);
        ethereum.on('chainChanged', handleChainChanged);
        ethereum.on('disconnect', handleDisconnect);
        
        return true;
      } else {
        console.warn('MetaMask not detected');
        return false;
      }
    } catch (error) {
      console.error('Failed to initialize Web3 provider:', error);
      return false;
    }
  }, []);

  // Handle account changes
  const handleAccountsChanged = useCallback(async (accounts) => {
    if (accounts.length === 0) {
      // User disconnected
      setAccount(null);
      setSigner(null);
      setIsConnected(false);
    } else {
      // User connected or switched accounts
      setAccount(accounts[0]);
      if (provider) {
        const web3Signer = await provider.getSigner();
        setSigner(web3Signer);
        setIsConnected(true);
        
        // Update contract with signer
        const contractWithSigner = contractService.getContract(web3Signer);
        setContract(contractWithSigner);
      }
    }
  }, [provider]);

  // Handle chain changes
  const handleChainChanged = useCallback((newChainId) => {
    const chainIdNumber = parseInt(newChainId, 16);
    setChainId(chainIdNumber);
    
    if (chainIdNumber !== SEPOLIA_CHAIN_ID) {
      toast.error('Please switch to Sepolia testnet');
    }
  }, [SEPOLIA_CHAIN_ID]);

  // Handle disconnect
  const handleDisconnect = useCallback(() => {
    setAccount(null);
    setSigner(null);
    setIsConnected(false);
    setChainId(null);
  }, []);

  // Connect wallet
  const connectWallet = async () => {
    try {
      setIsConnecting(true);
      setWeb3Loading(true);
      
      const ethereum = await detectEthereumProvider();
      if (!ethereum) {
        toast.error('MetaMask is not installed. Please install MetaMask to continue.');
        return { success: false, error: 'MetaMask not found' };
      }

      // Request account access
      const accounts = await ethereum.request({
        method: 'eth_requestAccounts',
      });

      if (accounts.length === 0) {
        toast.error('No accounts found. Please check your MetaMask.');
        return { success: false, error: 'No accounts' };
      }

      // Get network info
      const networkId = await ethereum.request({ method: 'eth_chainId' });
      const chainIdNumber = parseInt(networkId, 16);
      
      // Check if on correct network
      if (chainIdNumber !== SEPOLIA_CHAIN_ID) {
        const switched = await switchToSepolia();
        if (!switched) {
          return { success: false, error: 'Wrong network' };
        }
      }

      // Set up provider and signer
      const web3Provider = new BrowserProvider(ethereum);
      const web3Signer = await web3Provider.getSigner();
      
      setProvider(web3Provider);
      setSigner(web3Signer);
      setAccount(accounts[0]);
      setChainId(chainIdNumber);
      setIsConnected(true);
      
      // Initialize contract with signer
      const contractWithSigner = contractService.getContract(web3Signer);
      setContract(contractWithSigner);

      toast.success('Wallet connected successfully!');
      return { success: true, account: accounts[0] };

    } catch (error) {
      console.error('Failed to connect wallet:', error);
      
      let errorMessage = 'Failed to connect wallet';
      if (error.code === 4001) {
        errorMessage = 'Connection rejected by user';
      } else if (error.code === -32002) {
        errorMessage = 'Connection request already pending';
      }
      
      toast.error(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setIsConnecting(false);
      setWeb3Loading(false);
    }
  };

  // Disconnect wallet
  const disconnectWallet = () => {
    setAccount(null);
    setSigner(null);
    setIsConnected(false);
    setChainId(null);
    toast.success('Wallet disconnected');
  };

  // Switch to Sepolia network
  const switchToSepolia = async () => {
    try {
      const ethereum = await detectEthereumProvider();
      if (!ethereum) return false;

      await ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: `0x${SEPOLIA_CHAIN_ID.toString(16)}` }],
      });
      
      return true;
    } catch (error) {
      if (error.code === 4902) {
        // Network not added, try to add it
        try {
          await ethereum.request({
            method: 'wallet_addEthereumChain',
            params: [
              {
                chainId: `0x${SEPOLIA_CHAIN_ID.toString(16)}`,
                chainName: 'Sepolia Testnet',
                nativeCurrency: {
                  name: 'Sepolia ETH',
                  symbol: 'SEP',
                  decimals: 18,
                },
                rpcUrls: [SEPOLIA_RPC],
                blockExplorerUrls: ['https://sepolia.etherscan.io'],
              },
            ],
          });
          return true;
        } catch (addError) {
          console.error('Failed to add Sepolia network:', addError);
          toast.error('Failed to add Sepolia network');
          return false;
        }
      } else {
        console.error('Failed to switch to Sepolia:', error);
        toast.error('Failed to switch to Sepolia network');
        return false;
      }
    }
  };

  // Get balance
  const getBalance = async (address = account) => {
    try {
      if (!provider || !address) return null;
      
      const balance = await provider.getBalance(address);
      return ethers.formatEther(balance);
    } catch (error) {
      console.error('Failed to get balance:', error);
      return null;
    }
  };

  // Sign message
  const signMessage = async (message) => {
    try {
      if (!signer) {
        throw new Error('No signer available');
      }
      
      const signature = await signer.signMessage(message);
      return { success: true, signature };
    } catch (error) {
      console.error('Failed to sign message:', error);
      
      let errorMessage = 'Failed to sign message';
      if (error.code === 4001) {
        errorMessage = 'Signature rejected by user';
      }
      
      return { success: false, error: errorMessage };
    }
  };

  // Sign typed data (EIP-712)
  const signTypedData = async (domain, types, value) => {
    try {
      if (!signer) {
        throw new Error('No signer available');
      }
      
      const signature = await signer._signTypedData(domain, types, value);
      return { success: true, signature };
    } catch (error) {
      console.error('Failed to sign typed data:', error);
      
      let errorMessage = 'Failed to sign typed data';
      if (error.code === 4001) {
        errorMessage = 'Signature rejected by user';
      }
      
      return { success: false, error: errorMessage };
    }
  };

  // Check if on correct network
  const isCorrectNetwork = () => {
    return chainId === SEPOLIA_CHAIN_ID;
  };

  // Format address for display
  const formatAddress = (address) => {
    if (!address) return '';
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  // Initialize on mount
  useEffect(() => {
    initializeProvider();
  }, [initializeProvider]);

  const value = {
    // State
    provider,
    signer,
    account,
    chainId,
    isConnected,
    isConnecting,
    web3Loading,
    contract,
    
    // Actions
    connectWallet,
    disconnectWallet,
    switchToSepolia,
    getBalance,
    signMessage,
    signTypedData,
    
    // Utilities
    isCorrectNetwork,
    formatAddress,
    SEPOLIA_CHAIN_ID,
  };

  return (
    <Web3Context.Provider value={value}>
      {children}
    </Web3Context.Provider>
  );
};
