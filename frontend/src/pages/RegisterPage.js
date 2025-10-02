import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { 
  EyeIcon, 
  EyeOffIcon, 
  ShieldCheckIcon,
  LockClosedIcon,
  UserIcon,
  MailIcon
} from '@heroicons/react/outline';

import { useAuth } from '../contexts/AuthContext';
import { useWeb3 } from '../contexts/Web3Context';
import LoadingSpinner from '../components/UI/LoadingSpinner';

// Validation schema
const schema = yup.object({
  username: yup
    .string()
    .required('Username is required')
    .min(3, 'Username must be at least 3 characters')
    .max(50, 'Username cannot exceed 50 characters')
    .matches(/^[a-zA-Z0-9_-]+$/, 'Username can only contain letters, numbers, underscores, and hyphens'),
  email: yup
    .string()
    .required('Email is required')
    .email('Please enter a valid email address'),
  password: yup
    .string()
    .required('Password is required')
    .min(8, 'Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  confirmPassword: yup
    .string()
    .required('Please confirm your password')
    .oneOf([yup.ref('password')], 'Passwords must match'),
  firstName: yup
    .string()
    .max(50, 'First name cannot exceed 50 characters'),
  lastName: yup
    .string()
    .max(50, 'Last name cannot exceed 50 characters'),
  organization: yup
    .string()
    .max(100, 'Organization name cannot exceed 100 characters'),
  terms: yup
    .boolean()
    .oneOf([true], 'You must accept the terms and conditions')
});

const RegisterPage = () => {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const { register: registerUser, loading } = useAuth();
  const { account, connectWallet, isConnected } = useWeb3();
  const navigate = useNavigate();

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
      const registrationData = {
        username: data.username,
        email: data.email,
        password: data.password,
        firstName: data.firstName,
        lastName: data.lastName,
        organization: data.organization,
        ...(isConnected && account && { walletAddress: account })
      };

      const result = await registerUser(registrationData);
      
      if (result.success) {
        navigate('/login', { 
          state: { 
            message: 'Registration successful! Please sign in to continue.' 
          }
        });
      } else {
        setError('root', {
          type: 'manual',
          message: result.error?.message || 'Registration failed'
        });
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
        <title>Sign Up - SSI System</title>
        <meta name="description" content="Create your SSI System account to start managing your digital identity and credentials securely." />
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
            Create your account
          </h2>
          <p className="text-center text-sm text-gray-600">
            Join the future of digital identity
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

                {/* Username Field */}
                <div>
                  <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                    Username *
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <UserIcon className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('username')}
                      type="text"
                      className={`input pl-10 ${errors.username ? 'input-error' : ''}`}
                      placeholder="Choose a username"
                      autoComplete="username"
                    />
                  </div>
                  {errors.username && (
                    <p className="mt-1 text-sm text-error-600">{errors.username.message}</p>
                  )}
                </div>

                {/* Email Field */}
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                    Email Address *
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <MailIcon className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('email')}
                      type="email"
                      className={`input pl-10 ${errors.email ? 'input-error' : ''}`}
                      placeholder="Enter your email"
                      autoComplete="email"
                    />
                  </div>
                  {errors.email && (
                    <p className="mt-1 text-sm text-error-600">{errors.email.message}</p>
                  )}
                </div>

                {/* Name Fields */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="firstName" className="block text-sm font-medium text-gray-700 mb-1">
                      First Name
                    </label>
                    <input
                      {...register('firstName')}
                      type="text"
                      className={`input ${errors.firstName ? 'input-error' : ''}`}
                      placeholder="First name"
                      autoComplete="given-name"
                    />
                    {errors.firstName && (
                      <p className="mt-1 text-sm text-error-600">{errors.firstName.message}</p>
                    )}
                  </div>

                  <div>
                    <label htmlFor="lastName" className="block text-sm font-medium text-gray-700 mb-1">
                      Last Name
                    </label>
                    <input
                      {...register('lastName')}
                      type="text"
                      className={`input ${errors.lastName ? 'input-error' : ''}`}
                      placeholder="Last name"
                      autoComplete="family-name"
                    />
                    {errors.lastName && (
                      <p className="mt-1 text-sm text-error-600">{errors.lastName.message}</p>
                    )}
                  </div>
                </div>

                {/* Organization Field */}
                <div>
                  <label htmlFor="organization" className="block text-sm font-medium text-gray-700 mb-1">
                    Organization (Optional)
                  </label>
                  <input
                    {...register('organization')}
                    type="text"
                    className={`input ${errors.organization ? 'input-error' : ''}`}
                    placeholder="Your organization"
                    autoComplete="organization"
                  />
                  {errors.organization && (
                    <p className="mt-1 text-sm text-error-600">{errors.organization.message}</p>
                  )}
                </div>

                {/* Password Field */}
                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                    Password *
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <LockClosedIcon className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('password')}
                      type={showPassword ? 'text' : 'password'}
                      className={`input pl-10 pr-10 ${errors.password ? 'input-error' : ''}`}
                      placeholder="Create a strong password"
                      autoComplete="new-password"
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

                {/* Confirm Password Field */}
                <div>
                  <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-1">
                    Confirm Password *
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <LockClosedIcon className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('confirmPassword')}
                      type={showConfirmPassword ? 'text' : 'password'}
                      className={`input pl-10 pr-10 ${errors.confirmPassword ? 'input-error' : ''}`}
                      placeholder="Confirm your password"
                      autoComplete="new-password"
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    >
                      {showConfirmPassword ? (
                        <EyeOffIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      ) : (
                        <EyeIcon className="h-5 w-5 text-gray-400 hover:text-gray-600" />
                      )}
                    </button>
                  </div>
                  {errors.confirmPassword && (
                    <p className="mt-1 text-sm text-error-600">{errors.confirmPassword.message}</p>
                  )}
                </div>

                {/* Wallet Connection Option */}
                {!isConnected && (
                  <div className="bg-gray-50 border border-gray-200 rounded-md p-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-gray-900">Connect Wallet (Optional)</p>
                        <p className="text-xs text-gray-600">
                          Link your MetaMask wallet to your account
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

                {/* Wallet Connected Status */}
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

                {/* Terms and Conditions */}
                <div className="flex items-start">
                  <input
                    {...register('terms')}
                    type="checkbox"
                    className="mt-1 h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <div className="ml-3">
                    <label htmlFor="terms" className="text-sm text-gray-700">
                      I agree to the{' '}
                      <Link to="/terms" className="text-primary-600 hover:text-primary-500">
                        Terms of Service
                      </Link>{' '}
                      and{' '}
                      <Link to="/privacy" className="text-primary-600 hover:text-primary-500">
                        Privacy Policy
                      </Link>
                    </label>
                    {errors.terms && (
                      <p className="mt-1 text-sm text-error-600">{errors.terms.message}</p>
                    )}
                  </div>
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={isSubmitting || loading}
                  className="btn btn-primary w-full"
                >
                  {isSubmitting || loading ? (
                    <LoadingSpinner size="sm" color="white" />
                  ) : (
                    'Create Account'
                  )}
                </button>
              </form>
            </div>
          </div>

          {/* Sign In Link */}
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600">
              Already have an account?{' '}
              <Link
                to="/login"
                className="font-medium text-primary-600 hover:text-primary-500"
              >
                Sign in here
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

export default RegisterPage;
