import React from 'react';

const LoadingSpinner = ({ 
  size = 'md', 
  color = 'primary', 
  text = '', 
  fullScreen = false,
  className = '' 
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
    xl: 'w-16 h-16'
  };

  const colorClasses = {
    primary: 'border-primary-600',
    white: 'border-white',
    gray: 'border-gray-600',
    success: 'border-success-600',
    warning: 'border-warning-600',
    error: 'border-error-600'
  };

  const spinnerClasses = `
    ${sizeClasses[size]} 
    border-2 border-gray-200 border-t-transparent 
    ${colorClasses[color]} 
    rounded-full animate-spin
    ${className}
  `;

  const content = (
    <div className="flex flex-col items-center justify-center space-y-3">
      <div className={spinnerClasses}></div>
      {text && (
        <p className="text-sm text-gray-600 animate-pulse">
          {text}
        </p>
      )}
    </div>
  );

  if (fullScreen) {
    return (
      <div className="fixed inset-0 bg-white bg-opacity-90 flex items-center justify-center z-50">
        {content}
      </div>
    );
  }

  return content;
};

export default LoadingSpinner;
