import React from 'react';
import { Link } from 'react-router-dom';
import { Helmet } from 'react-helmet-async';
import { 
  ShieldCheckIcon, 
  CreditCardIcon, 
  GlobeAltIcon,
  LockClosedIcon,
  UserGroupIcon,
  CheckCircleIcon,
  ArrowRightIcon
} from '@heroicons/react/outline';

const HomePage = () => {
  const features = [
    {
      icon: ShieldCheckIcon,
      title: 'Secure Identity',
      description: 'Your identity is cryptographically secured and tamper-proof on the blockchain.'
    },
    {
      icon: LockClosedIcon,
      title: 'Privacy First',
      description: 'You control what information to share and with whom, maintaining full privacy.'
    },
    {
      icon: GlobeAltIcon,
      title: 'Decentralized',
      description: 'No central authority controls your identity. It\'s truly yours and portable.'
    },
    {
      icon: CreditCardIcon,
      title: 'Verifiable Credentials',
      description: 'Issue and verify credentials instantly without intermediaries.'
    },
    {
      icon: UserGroupIcon,
      title: 'Trusted Network',
      description: 'Join a network of verified issuers and trusted credential holders.'
    },
    {
      icon: CheckCircleIcon,
      title: 'Instant Verification',
      description: 'Verify credentials in seconds with cryptographic proof of authenticity.'
    }
  ];

  const stats = [
    { label: 'Credentials Issued', value: '10,000+' },
    { label: 'Verified Issuers', value: '500+' },
    { label: 'Active Users', value: '5,000+' },
    { label: 'Verifications', value: '50,000+' }
  ];

  return (
    <>
      <Helmet>
        <title>SSI System - Self-Sovereign Identity Platform</title>
        <meta name="description" content="Secure, decentralized digital identity management powered by blockchain technology. Issue, verify, and manage credentials with complete privacy and control." />
      </Helmet>

      <div className="min-h-screen bg-white">
        {/* Navigation */}
        <nav className="bg-white shadow-sm">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <div className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-gradient-primary rounded-lg flex items-center justify-center">
                  <ShieldCheckIcon className="w-5 h-5 text-white" />
                </div>
                <span className="text-xl font-bold text-gray-900">SSI System</span>
              </div>
              
              <div className="flex items-center space-x-4">
                <Link 
                  to="/verify" 
                  className="text-gray-600 hover:text-gray-900 px-3 py-2 text-sm font-medium"
                >
                  Verify Credential
                </Link>
                <Link 
                  to="/issuers" 
                  className="text-gray-600 hover:text-gray-900 px-3 py-2 text-sm font-medium"
                >
                  Issuers
                </Link>
                <Link 
                  to="/login" 
                  className="text-gray-600 hover:text-gray-900 px-3 py-2 text-sm font-medium"
                >
                  Sign In
                </Link>
                <Link 
                  to="/register" 
                  className="btn btn-primary"
                >
                  Get Started
                </Link>
              </div>
            </div>
          </div>
        </nav>

        {/* Hero Section */}
        <section className="relative overflow-hidden">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
            <div className="text-center">
              <h1 className="text-4xl md:text-6xl font-bold text-gray-900 mb-6">
                Your Identity,{' '}
                <span className="text-gradient-primary">Your Control</span>
              </h1>
              <p className="text-xl text-gray-600 mb-8 max-w-3xl mx-auto">
                Take control of your digital identity with our blockchain-powered 
                Self-Sovereign Identity system. Issue, verify, and manage credentials 
                with complete privacy and security.
              </p>
              
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Link 
                  to="/register" 
                  className="btn btn-primary btn-lg hover-lift"
                >
                  Start Your Journey
                  <ArrowRightIcon className="w-5 h-5 ml-2" />
                </Link>
                <Link 
                  to="/verify" 
                  className="btn btn-outline btn-lg hover-lift"
                >
                  Verify Credential
                </Link>
              </div>
            </div>
          </div>
          
          {/* Background decoration */}
          <div className="absolute inset-0 -z-10">
            <div className="absolute top-0 left-1/2 transform -translate-x-1/2 w-96 h-96 bg-gradient-primary opacity-10 rounded-full blur-3xl"></div>
            <div className="absolute bottom-0 right-0 w-64 h-64 bg-gradient-success opacity-10 rounded-full blur-3xl"></div>
          </div>
        </section>

        {/* Stats Section */}
        <section className="bg-gray-50 py-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
              {stats.map((stat, index) => (
                <div key={index} className="text-center">
                  <div className="text-3xl font-bold text-primary-600 mb-2">
                    {stat.value}
                  </div>
                  <div className="text-sm text-gray-600">
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="py-24">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-16">
              <h2 className="text-3xl font-bold text-gray-900 mb-4">
                Why Choose Self-Sovereign Identity?
              </h2>
              <p className="text-lg text-gray-600 max-w-2xl mx-auto">
                Experience the future of digital identity with cutting-edge blockchain 
                technology that puts you in complete control.
              </p>
            </div>
            
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
              {features.map((feature, index) => {
                const Icon = feature.icon;
                return (
                  <div key={index} className="card hover-lift">
                    <div className="card-body text-center">
                      <div className="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center mx-auto mb-4">
                        <Icon className="w-6 h-6 text-primary-600" />
                      </div>
                      <h3 className="text-xl font-semibold text-gray-900 mb-2">
                        {feature.title}
                      </h3>
                      <p className="text-gray-600">
                        {feature.description}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* How it Works Section */}
        <section className="bg-gray-50 py-24">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-16">
              <h2 className="text-3xl font-bold text-gray-900 mb-4">
                How It Works
              </h2>
              <p className="text-lg text-gray-600">
                Simple steps to get started with your digital identity
              </p>
            </div>
            
            <div className="grid md:grid-cols-3 gap-8">
              <div className="text-center">
                <div className="w-16 h-16 bg-primary-600 text-white rounded-full flex items-center justify-center mx-auto mb-4 text-xl font-bold">
                  1
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  Create Account
                </h3>
                <p className="text-gray-600">
                  Sign up and connect your MetaMask wallet to get started with your digital identity.
                </p>
              </div>
              
              <div className="text-center">
                <div className="w-16 h-16 bg-primary-600 text-white rounded-full flex items-center justify-center mx-auto mb-4 text-xl font-bold">
                  2
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  Get Credentials
                </h3>
                <p className="text-gray-600">
                  Receive verifiable credentials from trusted issuers or become an issuer yourself.
                </p>
              </div>
              
              <div className="text-center">
                <div className="w-16 h-16 bg-primary-600 text-white rounded-full flex items-center justify-center mx-auto mb-4 text-xl font-bold">
                  3
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  Share & Verify
                </h3>
                <p className="text-gray-600">
                  Share your credentials securely and verify others' credentials instantly.
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="gradient-primary py-24">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
            <h2 className="text-3xl font-bold text-white mb-4">
              Ready to Take Control of Your Identity?
            </h2>
            <p className="text-xl text-white opacity-90 mb-8 max-w-2xl mx-auto">
              Join thousands of users who have already embraced the future of digital identity.
            </p>
            <Link 
              to="/register" 
              className="btn bg-white text-primary-600 hover:bg-gray-100 btn-lg hover-lift"
            >
              Get Started Today
              <ArrowRightIcon className="w-5 h-5 ml-2" />
            </Link>
          </div>
        </section>

        {/* Footer */}
        <footer className="bg-gray-900 text-white py-12">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="grid md:grid-cols-4 gap-8">
              <div>
                <div className="flex items-center space-x-2 mb-4">
                  <div className="w-8 h-8 bg-gradient-primary rounded-lg flex items-center justify-center">
                    <ShieldCheckIcon className="w-5 h-5 text-white" />
                  </div>
                  <span className="text-xl font-bold">SSI System</span>
                </div>
                <p className="text-gray-400">
                  Empowering individuals with self-sovereign digital identity.
                </p>
              </div>
              
              <div>
                <h3 className="font-semibold mb-4">Platform</h3>
                <ul className="space-y-2 text-gray-400">
                  <li><Link to="/verify" className="hover:text-white">Verify Credentials</Link></li>
                  <li><Link to="/issuers" className="hover:text-white">Browse Issuers</Link></li>
                  <li><Link to="/register" className="hover:text-white">Get Started</Link></li>
                </ul>
              </div>
              
              <div>
                <h3 className="font-semibold mb-4">Resources</h3>
                <ul className="space-y-2 text-gray-400">
                  <li><a href="#" className="hover:text-white">Documentation</a></li>
                  <li><a href="#" className="hover:text-white">API Reference</a></li>
                  <li><a href="#" className="hover:text-white">Support</a></li>
                </ul>
              </div>
              
              <div>
                <h3 className="font-semibold mb-4">Legal</h3>
                <ul className="space-y-2 text-gray-400">
                  <li><a href="#" className="hover:text-white">Privacy Policy</a></li>
                  <li><a href="#" className="hover:text-white">Terms of Service</a></li>
                  <li><a href="#" className="hover:text-white">Cookie Policy</a></li>
                </ul>
              </div>
            </div>
            
            <div className="border-t border-gray-800 mt-8 pt-8 text-center text-gray-400">
              <p>&copy; 2024 SSI System. All rights reserved.</p>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
};

export default HomePage;
