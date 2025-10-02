import React, { useState } from 'react';
import { 
  CreditCardIcon as WalletIcon, 
  ExclamationIcon as ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon 
} from '@heroicons/react/outline';
import { useWeb3 } from '../../contexts/Web3Context';
import { formatAddress } from '../../utils/web3';
import LoadingSpinner from '../UI/LoadingSpinner';

const WalletConnection = ({ compact = false }) => {
  const {
    account,
    isConnected,
    isConnecting,
    chainId,
    connectWallet,
    disconnectWallet,
    switchToSepolia,
    isCorrectNetwork,
    getBalance,
    SEPOLIA_CHAIN_ID
  } = useWeb3();

  const [balance, setBalance] = useState(null);
  const [showDetails, setShowDetails] = useState(false);

  // Load balance when connected
  React.useEffect(() => {
    if (isConnected && account) {
      getBalance(account).then(setBalance);
    } else {
      setBalance(null);
    }
  }, [isConnected, account, getBalance]);

  const handleConnect = async () => {
    const result = await connectWallet();
    if (result.success) {
      // Wallet connected successfully
    }
  };

  const handleNetworkSwitch = async () => {
    await switchToSepolia();
  };

  if (compact) {
    return (
      <div className="flex items-center space-x-2">
        {isConnected ? (
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
            <span className="text-sm text-gray-600">
              {formatAddress(account)}
            </span>
          </div>
        ) : (
          <button
            onClick={handleConnect}
            disabled={isConnecting}
            className="btn btn-sm btn-primary"
          >
            {isConnecting ? (
              <LoadingSpinner size="sm" color="white" />
            ) : (
              <>
                <WalletIcon className="w-4 h-4 mr-1" />
                Connect
              </>
            )}
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="bg-gray-50 rounded-lg p-3">
      {!isConnected ? (
        <div className="text-center">
          <WalletIcon className="w-8 h-8 text-gray-400 mx-auto mb-2" />
          <p className="text-sm text-gray-600 mb-3">
            Connect your wallet to interact with the blockchain
          </p>
          <button
            onClick={handleConnect}
            disabled={isConnecting}
            className="btn btn-sm btn-primary w-full"
          >
            {isConnecting ? (
              <LoadingSpinner size="sm" color="white" />
            ) : (
              <>
                <WalletIcon className="w-4 h-4 mr-2" />
                Connect Wallet
              </>
            )}
          </button>
        </div>
      ) : (
        <div>
          {/* Connection Status */}
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <CheckCircleIcon className="w-4 h-4 text-green-500" />
              <span className="text-sm font-medium text-gray-900">
                Wallet Connected
              </span>
            </div>
            <button
              onClick={() => setShowDetails(!showDetails)}
              className="text-xs text-gray-500 hover:text-gray-700"
            >
              {showDetails ? 'Hide' : 'Show'} Details
            </button>
          </div>

          {/* Network Warning */}
          {!isCorrectNetwork() && (
            <div className="bg-warning-50 border border-warning-200 rounded-md p-2 mb-2">
              <div className="flex items-center">
                <ExclamationTriangleIcon className="w-4 h-4 text-warning-600 mr-2" />
                <div className="flex-1">
                  <p className="text-xs text-warning-800">
                    Wrong network. Please switch to Sepolia.
                  </p>
                </div>
                <button
                  onClick={handleNetworkSwitch}
                  className="text-xs text-warning-600 hover:text-warning-800 font-medium"
                >
                  Switch
                </button>
              </div>
            </div>
          )}

          {/* Wallet Address */}
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-600">
              {formatAddress(account, 6)}
            </span>
            <button
              onClick={disconnectWallet}
              className="text-xs text-gray-500 hover:text-red-600"
            >
              Disconnect
            </button>
          </div>

          {/* Detailed Information */}
          {showDetails && (
            <div className="mt-3 pt-3 border-t border-gray-200 space-y-2">
              <div className="flex justify-between text-xs">
                <span className="text-gray-500">Network:</span>
                <span className="text-gray-900">
                  {chainId === SEPOLIA_CHAIN_ID ? 'Sepolia' : `Chain ${chainId}`}
                </span>
              </div>
              
              {balance && (
                <div className="flex justify-between text-xs">
                  <span className="text-gray-500">Balance:</span>
                  <span className="text-gray-900">
                    {parseFloat(balance).toFixed(4)} SEP
                  </span>
                </div>
              )}
              
              <div className="flex justify-between text-xs">
                <span className="text-gray-500">Address:</span>
                <button
                  onClick={() => navigator.clipboard.writeText(account)}
                  className="text-primary-600 hover:text-primary-800 font-mono"
                  title="Copy address"
                >
                  {formatAddress(account, 8)}
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default WalletConnection;
