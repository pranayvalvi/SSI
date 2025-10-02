import React from 'react';
import { Helmet } from 'react-helmet-async';

const CredentialIssuePage = () => {
  return (
    <>
      <Helmet>
        <title>Issue Credential - SSI System</title>
      </Helmet>
      <div className="text-center py-12">
        <h1 className="text-2xl font-bold text-gray-900 mb-4">Issue Credential</h1>
        <p className="text-gray-600">Credential issuance coming soon...</p>
      </div>
    </>
  );
};

export default CredentialIssuePage;
