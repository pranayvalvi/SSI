import React from 'react';
import { Helmet } from 'react-helmet-async';

const CredentialsPage = () => {
  return (
    <>
      <Helmet>
        <title>My Credentials - SSI System</title>
      </Helmet>
      <div className="text-center py-12">
        <h1 className="text-2xl font-bold text-gray-900 mb-4">My Credentials</h1>
        <p className="text-gray-600">Credentials management coming soon...</p>
      </div>
    </>
  );
};

export default CredentialsPage;
