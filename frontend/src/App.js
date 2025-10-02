import React, { Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';

// Context hooks
import { useAuth } from './contexts/AuthContext';
import { useWeb3 } from './contexts/Web3Context';

// Layout components
import Layout from './components/Layout/Layout';
import LoadingSpinner from './components/UI/LoadingSpinner';

// Lazy load pages for better performance
const HomePage = React.lazy(() => import('./pages/HomePage'));
const LoginPage = React.lazy(() => import('./pages/LoginPage'));
const RegisterPage = React.lazy(() => import('./pages/RegisterPage'));
const DashboardPage = React.lazy(() => import('./pages/DashboardPage'));
const ProfilePage = React.lazy(() => import('./pages/ProfilePage'));
const IssuerRegistrationPage = React.lazy(() => import('./pages/IssuerRegistrationPage'));
const IssuerDashboardPage = React.lazy(() => import('./pages/IssuerDashboardPage'));
const CredentialIssuePage = React.lazy(() => import('./pages/CredentialIssuePage'));
const CredentialVerifyPage = React.lazy(() => import('./pages/CredentialVerifyPage'));
const CredentialsPage = React.lazy(() => import('./pages/CredentialsPage'));
const IssuersPage = React.lazy(() => import('./pages/IssuersPage'));
const NotFoundPage = React.lazy(() => import('./pages/NotFoundPage'));

// Protected route component
const ProtectedRoute = ({ children, requireIssuer = false }) => {
  const { user, isAuthenticated, loading } = useAuth();

  if (loading) {
    return <LoadingSpinner />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (requireIssuer && user?.role !== 'issuer' && user?.role !== 'admin') {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

// Public route component (redirect if already authenticated)
const PublicRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return <LoadingSpinner />;
  }

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

function App() {
  const { web3Loading } = useWeb3();

  return (
    <>
      <Helmet>
        <title>SSI System - Self-Sovereign Identity</title>
        <meta name="description" content="Secure, decentralized digital identity management powered by blockchain technology" />
      </Helmet>

      <div className="min-h-screen bg-gray-50">
        {web3Loading && (
          <div className="fixed top-0 left-0 right-0 z-50 bg-primary-600 text-white text-center py-2 text-sm">
            <div className="flex items-center justify-center space-x-2">
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              <span>Connecting to Web3...</span>
            </div>
          </div>
        )}

        <Suspense fallback={<LoadingSpinner />}>
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<HomePage />} />
            <Route path="/verify" element={<CredentialVerifyPage />} />
            <Route path="/issuers" element={<IssuersPage />} />
            
            {/* Authentication routes */}
            <Route 
              path="/login" 
              element={
                <PublicRoute>
                  <LoginPage />
                </PublicRoute>
              } 
            />
            <Route 
              path="/register" 
              element={
                <PublicRoute>
                  <RegisterPage />
                </PublicRoute>
              } 
            />

            {/* Protected routes */}
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute>
                  <Layout>
                    <DashboardPage />
                  </Layout>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/profile" 
              element={
                <ProtectedRoute>
                  <Layout>
                    <ProfilePage />
                  </Layout>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/credentials" 
              element={
                <ProtectedRoute>
                  <Layout>
                    <CredentialsPage />
                  </Layout>
                </ProtectedRoute>
              } 
            />

            {/* Issuer routes */}
            <Route 
              path="/become-issuer" 
              element={
                <ProtectedRoute>
                  <Layout>
                    <IssuerRegistrationPage />
                  </Layout>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/issuer/dashboard" 
              element={
                <ProtectedRoute requireIssuer>
                  <Layout>
                    <IssuerDashboardPage />
                  </Layout>
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/issuer/issue" 
              element={
                <ProtectedRoute requireIssuer>
                  <Layout>
                    <CredentialIssuePage />
                  </Layout>
                </ProtectedRoute>
              } 
            />

            {/* 404 route */}
            <Route path="*" element={<NotFoundPage />} />
          </Routes>
        </Suspense>
      </div>
    </>
  );
}

export default App;
