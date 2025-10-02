import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';
import {
  CreditCardIcon,
  ShieldCheckIcon,
  UserGroupIcon,
  TrendingUpIcon,
  PlusIcon,
  EyeIcon,
  ClockIcon,
  CheckCircleIcon,
  ExclamationIcon as ExclamationTriangleIcon
} from '@heroicons/react/outline';

import { useAuth } from '../contexts/AuthContext';
import { useWeb3 } from '../contexts/Web3Context';
import { credentialAPI, issuerAPI } from '../services/api';
import LoadingSpinner from '../components/UI/LoadingSpinner';
import WalletConnection from '../components/Web3/WalletConnection';

const DashboardPage = () => {
  const { user, isIssuer } = useAuth();
  const { isConnected, account } = useWeb3();
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    credentials: 0,
    verifications: 0,
    issuedCredentials: 0,
    activeIssuers: 0
  });
  const [recentCredentials, setRecentCredentials] = useState([]);
  const [issuerProfile, setIssuerProfile] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, [user]);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      
      // Load user credentials
      const credentialsResponse = await credentialAPI.getAll({ limit: 5 });
      if (credentialsResponse.success) {
        setRecentCredentials(credentialsResponse.data.credentials);
        setStats(prev => ({
          ...prev,
          credentials: credentialsResponse.data.pagination.totalDocs
        }));
      }

      // Load issuer profile if user is an issuer
      if (isIssuer()) {
        const issuerResponse = await issuerAPI.getMyProfile();
        if (issuerResponse.success) {
          setIssuerProfile(issuerResponse.data.issuer);
          setStats(prev => ({
            ...prev,
            issuedCredentials: issuerResponse.data.issuer.statistics.credentialsIssued
          }));
        }
      }

      // Load general stats
      const issuersResponse = await issuerAPI.getAll({ limit: 1 });
      if (issuersResponse.success) {
        setStats(prev => ({
          ...prev,
          activeIssuers: issuersResponse.data.pagination.totalDocs
        }));
      }

    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getCredentialStatusIcon = (credential) => {
    if (credential.status === 'revoked') {
      return <ExclamationTriangleIcon className="w-5 h-5 text-error-500" />;
    }
    if (credential.isExpired) {
      return <ClockIcon className="w-5 h-5 text-warning-500" />;
    }
    return <CheckCircleIcon className="w-5 h-5 text-success-500" />;
  };

  const getCredentialStatusText = (credential) => {
    if (credential.status === 'revoked') return 'Revoked';
    if (credential.isExpired) return 'Expired';
    return 'Valid';
  };

  const getCredentialStatusColor = (credential) => {
    if (credential.status === 'revoked') return 'text-error-600';
    if (credential.isExpired) return 'text-warning-600';
    return 'text-success-600';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <LoadingSpinner size="lg" text="Loading dashboard..." />
      </div>
    );
  }

  return (
    <>
      <Helmet>
        <title>Dashboard - SSI System</title>
        <meta name="description" content="Manage your digital identity, credentials, and issuer profile from your SSI System dashboard." />
      </Helmet>

      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              Welcome back, {user?.username}!
            </h1>
            <p className="text-gray-600">
              Manage your digital identity and credentials
            </p>
          </div>
          
          {!isConnected && (
            <div className="mt-4 sm:mt-0">
              <WalletConnection compact />
            </div>
          )}
        </div>

        {/* Wallet Connection Alert */}
        {!isConnected && (
          <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
            <div className="flex items-start">
              <ExclamationTriangleIcon className="w-5 h-5 text-warning-600 mt-0.5 mr-3 flex-shrink-0" />
              <div>
                <h3 className="text-sm font-medium text-warning-800">
                  Wallet Not Connected
                </h3>
                <p className="text-sm text-warning-700 mt-1">
                  Connect your MetaMask wallet to interact with the blockchain and manage credentials.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="card hover-lift">
            <div className="card-body">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center">
                  <CreditCardIcon className="w-6 h-6 text-primary-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">My Credentials</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.credentials}</p>
                </div>
              </div>
            </div>
          </div>

          {isIssuer() && (
            <div className="card hover-lift">
              <div className="card-body">
                <div className="flex items-center">
                  <div className="w-12 h-12 bg-success-100 rounded-lg flex items-center justify-center">
                    <ShieldCheckIcon className="w-6 h-6 text-success-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Issued</p>
                    <p className="text-2xl font-bold text-gray-900">{stats.issuedCredentials}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="card hover-lift">
            <div className="card-body">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-warning-100 rounded-lg flex items-center justify-center">
                  <TrendingUpIcon className="w-6 h-6 text-warning-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Verifications</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.verifications}</p>
                </div>
              </div>
            </div>
          </div>

          <div className="card hover-lift">
            <div className="card-body">
              <div className="flex items-center">
                <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
                  <UserGroupIcon className="w-6 h-6 text-purple-600" />
                </div>
                <div className="ml-4">
                  <p className="text-sm font-medium text-gray-600">Active Issuers</p>
                  <p className="text-2xl font-bold text-gray-900">{stats.activeIssuers}</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <Link to="/credentials" className="card hover-lift group">
            <div className="card-body text-center">
              <CreditCardIcon className="w-8 h-8 text-primary-600 mx-auto mb-3 group-hover:scale-110 transition-transform" />
              <h3 className="text-lg font-semibold text-gray-900 mb-2">View Credentials</h3>
              <p className="text-gray-600">Manage and view all your verifiable credentials</p>
            </div>
          </Link>

          {!isIssuer() && (
            <Link to="/become-issuer" className="card hover-lift group">
              <div className="card-body text-center">
                <ShieldCheckIcon className="w-8 h-8 text-success-600 mx-auto mb-3 group-hover:scale-110 transition-transform" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Become Issuer</h3>
                <p className="text-gray-600">Register as a credential issuer</p>
              </div>
            </Link>
          )}

          {isIssuer() && (
            <Link to="/issuer/issue" className="card hover-lift group">
              <div className="card-body text-center">
                <PlusIcon className="w-8 h-8 text-success-600 mx-auto mb-3 group-hover:scale-110 transition-transform" />
                <h3 className="text-lg font-semibold text-gray-900 mb-2">Issue Credential</h3>
                <p className="text-gray-600">Create new verifiable credentials</p>
              </div>
            </Link>
          )}

          <Link to="/verify" className="card hover-lift group">
            <div className="card-body text-center">
              <EyeIcon className="w-8 h-8 text-warning-600 mx-auto mb-3 group-hover:scale-110 transition-transform" />
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Verify Credential</h3>
              <p className="text-gray-600">Verify the authenticity of credentials</p>
            </div>
          </Link>
        </div>

        {/* Recent Credentials */}
        <div className="card">
          <div className="card-header">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">Recent Credentials</h2>
              <Link to="/credentials" className="text-sm text-primary-600 hover:text-primary-700">
                View all
              </Link>
            </div>
          </div>
          <div className="card-body">
            {recentCredentials.length === 0 ? (
              <div className="text-center py-8">
                <CreditCardIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">No credentials yet</h3>
                <p className="text-gray-600 mb-4">
                  You haven't received any credentials yet. Get started by connecting with issuers.
                </p>
                <Link to="/issuers" className="btn btn-primary">
                  Browse Issuers
                </Link>
              </div>
            ) : (
              <div className="space-y-4">
                {recentCredentials.map((credential) => (
                  <div key={credential.id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                    <div className="flex items-center space-x-4">
                      <div className="w-10 h-10 bg-white rounded-lg flex items-center justify-center shadow-sm">
                        {getCredentialStatusIcon(credential)}
                      </div>
                      <div>
                        <h4 className="text-sm font-medium text-gray-900">
                          {credential.credentialType.replace('Credential', '')} Credential
                        </h4>
                        <p className="text-sm text-gray-600">
                          Issued by {credential.issuer.name}
                        </p>
                        <p className="text-xs text-gray-500">
                          {new Date(credential.issuedAt).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-4">
                      <span className={`text-sm font-medium ${getCredentialStatusColor(credential)}`}>
                        {getCredentialStatusText(credential)}
                      </span>
                      <Link
                        to={`/credentials/${credential.id}`}
                        className="text-primary-600 hover:text-primary-700"
                      >
                        <EyeIcon className="w-5 h-5" />
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Issuer Profile Summary */}
        {isIssuer() && issuerProfile && (
          <div className="card">
            <div className="card-header">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-gray-900">Issuer Profile</h2>
                <Link to="/issuer/dashboard" className="text-sm text-primary-600 hover:text-primary-700">
                  Manage
                </Link>
              </div>
            </div>
            <div className="card-body">
              <div className="flex items-center space-x-4">
                <div className="w-16 h-16 bg-gradient-primary rounded-lg flex items-center justify-center">
                  <ShieldCheckIcon className="w-8 h-8 text-white" />
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-gray-900">{issuerProfile.name}</h3>
                  <p className="text-gray-600">{issuerProfile.description}</p>
                  <div className="flex items-center space-x-4 mt-2">
                    <span className={`badge ${
                      issuerProfile.status === 'active' ? 'badge-success' : 
                      issuerProfile.status === 'pending' ? 'badge-warning' : 'badge-error'
                    }`}>
                      {issuerProfile.status}
                    </span>
                    <span className="text-sm text-gray-600">
                      Verification Level: {issuerProfile.verificationLevel}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
};

export default DashboardPage;
