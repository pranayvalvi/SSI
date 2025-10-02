import React from 'react';
import { Helmet } from 'react-helmet-async';

const CredentialVerifyPage = () => {
  return (
    <>
      <Helmet>
        <title>Verify Credential - SSI System</title>
      </Helmet>
      <div className="text-center py-12">
        <h1 className="text-2xl font-bold text-gray-900 mb-4">Verify Credential</h1>
        <p className="text-gray-600">Credential verification coming soon...</p>
      </div>
    </>
  );
};

export default CredentialVerifyPage;
