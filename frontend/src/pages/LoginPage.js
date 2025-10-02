import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { 
  EyeIcon, 
  EyeOffIcon, 
  ShieldCheckIcon,
  LockClosedIcon,
  UserIcon
} from '@heroicons/react/outline';

import { useAuth } from '../contexts/AuthContext';
import { useWeb3 } from '../contexts/Web3Context';
import LoadingSpinner from '../components/UI/LoadingSpinner';

// Validation schema
const schema = yup.object({
  identifier: yup
    .string()
    .required('Username or email is required')
    .min(3, 'Must be at least 3 characters'),
  password: yup
    .string()
    .required('Password is required')
    .min(8, 'Password must be at least 8 characters'),
});

const LoginPage = () => {
  const [showPassword, setShowPassword] = useState(false);
  const { login, loading } = useAuth();
  const { account, connectWallet, isConnected } = useWeb3();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/dashboard';

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError
  } = useForm({
    resolver: yupResolver(schema)
  });

  const onSubmit = async (data) => {
    try {
      // Add wallet address if connected
      const loginData = {
        ...data,
        ...(isConnected && account && { walletAddress: account })
      };

      const result = await login(loginData);
      
      if (result.success) {
        navigate(from, { replace: true });
      } else {
        if (result.error?.code === 'WALLET_ADDRESS_MISMATCH') {
          setError('root', {
            type: 'manual',
            message: 'Connected wallet does not match your account. Please connect the correct wallet or login without wallet connection.'
          });
        } else {
          setError('root', {
            type: 'manual',
            message: result.error?.message || 'Login failed'
          });
        }
      }
    } catch (error) {
      setError('root', {
        type: 'manual',
        message: 'An unexpected error occurred'
      });
    }
  };

  return (
    <>
      <Helmet>
        <title>Sign In - SSI System</title>
        <meta name="description" content="Sign in to your SSI System account to manage your digital identity and credentials." />
      </Helmet>

      <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          {/* Logo */}
          <Link to="/" className="flex items-center justify-center space-x-2 mb-6">
            <div className="w-10 h-10 bg-gradient-primary rounded-lg flex items-center justify-center">
              <ShieldCheckIcon className="w-6 h-6 text-white" />
            </div>
            <span className="text-2xl font-bold text-gray-900">SSI System</span>
          </Link>

          <h2 className="text-center text-3xl font-bold text-gray-900 mb-2">
            Welcome back
          </h2>
          <p className="text-center text-sm text-gray-600">
            Sign in to your account to continue
          </p>
        </div>

        <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
          <div className="card">
            <div className="card-body">
              <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
                {/* Global Error */}
                {errors.root && (
                  <div className="alert alert-error">
                    <p className="text-sm">{errors.root.message}</p>
                  </div>
                )}

                {/* Username/Email Field */}
                <div>
                  <label htmlFor="identifier" className="block text-sm font-medium text-gray-700 mb-1">
                    Username or Email
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <UserIcon className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('identifier')}
                      type="text"
                      className={`input pl-10 ${errors.identifier ? 'input-error' : ''}`}
                      placeholder="Enter your username or email"
                      autoComplete="username"
                    />
                  </div>
                  {errors.identifier && (
                    <p className="mt-1 text-sm text-error-600">{errors.identifier.message}</p>
                  )}
                </div>

                {/* Password Field */}
                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                    Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <LockClosedIcon className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('password')}
                      type={showPassword ? 'text' : 'password'}
                      className={`input pl-10 pr-10 ${errors.password ? 'input-error' : ''}`}
                      placeholder="Enter your password"
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? (
                        <EyeOffIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      ) : (
                        <EyeIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      )}
                    </button>
                  </div>
                  {errors.password && (
                    <p className="mt-1 text-sm text-error-600">{errors.password.message}</p>
                  )}
                </div>

                {/* Wallet Connection Status */}
                {isConnected && account && (
                  <div className="bg-success-50 border border-success-200 rounded-md p-3">
                    <div className="flex items-center">
                      <div className="w-2 h-2 bg-success-500 rounded-full mr-2"></div>
                      <span className="text-sm text-success-800">
                        Wallet connected: {account.slice(0, 6)}...{account.slice(-4)}
                      </span>
                    </div>
                  </div>
                )}

                {/* Connect Wallet Option */}
                {!isConnected && (
                  <div className="bg-gray-50 border border-gray-200 rounded-md p-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-900">Connect Wallet (Optional)</p>
                        <p className="text-xs text-gray-600">
                          Link your MetaMask wallet for enhanced security
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={connectWallet}
                        className="btn btn-sm btn-outline"
                      >
                        Connect
                      </button>
                    </div>
                  </div>
                )}

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={isSubmitting || loading}
                  className="btn btn-primary w-full"
                >
                  {isSubmitting || loading ? (
                    <LoadingSpinner size="sm" color="white" />
                  ) : (
                    'Sign In'
                  )}
                </button>

                {/* Forgot Password Link */}
                <div className="text-center">
                  <Link
                    to="/forgot-password"
                    className="text-sm text-primary-600 hover:text-primary-500"
                  >
                    Forgot your password?
                  </Link>
                </div>
              </form>
            </div>
          </div>

          {/* Sign Up Link */}
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              Don't have an account?{' '}
              <Link
                to="/register"
                className="font-medium text-primary-600 hover:text-primary-500"
              >
                Sign up for free
              </Link>
            </p>
          </div>

          {/* Back to Home */}
          <div className="mt-4 text-center">
            <Link
              to="/"
              className="text-sm text-gray-500 hover:text-gray-700"
            >
              ← Back to home
            </Link>
          </div>
        </div>
      </div>
    </>
  );
};

export default LoginPage;
