import React from 'react';
import { Link } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';
import { 
  HomeIcon, 
  ArrowLeftIcon,
  ExclamationIcon as ExclamationTriangleIcon 
} from '@heroicons/react/outline';

const NotFoundPage = () => {
  return (
    <>
      <Helmet>
        <title>Page Not Found - SSI System</title>
        <meta name="description" content="The page you're looking for doesn't exist." />
      </Helmet>

      <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-md">
          <div className="text-center">
            {/* 404 Icon */}
            <div className="mx-auto w-24 h-24 bg-error-100 rounded-full flex items-center justify-center mb-6">
              <ExclamationTriangleIcon className="w-12 h-12 text-error-600" />
            </div>

            {/* 404 Text */}
            <h1 className="text-6xl font-bold text-gray-900 mb-4">404</h1>
            
            <h2 className="text-2xl font-semibold text-gray-900 mb-2">
              Page Not Found
            </h2>
            
            <p className="text-gray-600 mb-8 max-w-md mx-auto">
              Sorry, we couldn't find the page you're looking for. 
              The page might have been moved, deleted, or you entered the wrong URL.
            </p>

            {/* Action Buttons */}
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <button
                onClick={() => window.history.back()}
                className="btn btn-outline inline-flex items-center"
              >
                <ArrowLeftIcon className="w-5 h-5 mr-2" />
                Go Back
              </button>
              
              <Link to="/" className="btn btn-primary inline-flex items-center">
                <HomeIcon className="w-5 h-5 mr-2" />
                Go Home
              </Link>
            </div>

            {/* Helpful Links */}
            <div className="mt-8 pt-8 border-t border-gray-200">
              <p className="text-sm text-gray-600 mb-4">
                Looking for something specific? Try these links:
              </p>
              
              <div className="space-y-2">
                <Link 
                  to="/dashboard" 
                  className="block text-sm text-primary-600 hover:text-primary-700"
                >
                  Dashboard
                </Link>
                <Link 
                  to="/credentials" 
                  className="block text-sm text-primary-600 hover:text-primary-700"
                >
                  My Credentials
                </Link>
                <Link 
                  to="/verify" 
                  className="block text-sm text-primary-600 hover:text-primary-700"
                >
                  Verify Credential
                </Link>
                <Link 
                  to="/issuers" 
                  className="block text-sm text-primary-600 hover:text-primary-700"
                >
                  Browse Issuers
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default NotFoundPage;
