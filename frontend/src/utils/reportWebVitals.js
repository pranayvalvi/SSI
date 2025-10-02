const reportWebVitals = onPerfEntry => {
  if (onPerfEntry && onPerfEntry instanceof Function) {
    // Web vitals reporting - can be enabled after installing web-vitals package
    try {
      import('web-vitals').then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
        getCLS(onPerfEntry);
        getFID(onPerfEntry);
        getFCP(onPerfEntry);
        getLCP(onPerfEntry);
        getTTFB(onPerfEntry);
      }).catch(() => {
        // web-vitals not installed, skip reporting
      });
    } catch (error) {
      // web-vitals not available, skip reporting
    }
  }
};

export default reportWebVitals;
