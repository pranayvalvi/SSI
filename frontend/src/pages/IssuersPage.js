import React from 'react';
import { Helmet } from 'react-helmet-async';

const IssuersPage = () => {
  return (
    <>
      <Helmet>
        <title>Browse Issuers - SSI System</title>
      </Helmet>
      <div className="text-center py-12">
        <h1 className="text-2xl font-bold text-gray-900 mb-4">Browse Issuers</h1>
        <p className="text-gray-600">Issuer directory coming soon...</p>
      </div>
    </>
  );
};

export default IssuersPage;
