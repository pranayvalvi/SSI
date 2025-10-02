import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext({});

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState('light');
  const [systemTheme, setSystemTheme] = useState('light');

  // Detect system theme preference
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    setSystemTheme(mediaQuery.matches ? 'dark' : 'light');

    const handleChange = (e) => {
      setSystemTheme(e.matches ? 'dark' : 'light');
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, []);

  // Load theme from localStorage or use system preference
  useEffect(() => {
    const savedTheme = localStorage.getItem('ssi-theme');
    if (savedTheme && ['light', 'dark', 'system'].includes(savedTheme)) {
      setTheme(savedTheme);
    } else {
      setTheme('system');
    }
  }, []);

  // Apply theme to document
  useEffect(() => {
    const effectiveTheme = theme === 'system' ? systemTheme : theme;
    
    if (effectiveTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    
    // Update meta theme-color
    const metaThemeColor = document.querySelector('meta[name="theme-color"]');
    if (metaThemeColor) {
      metaThemeColor.setAttribute('content', effectiveTheme === 'dark' ? '#1f2937' : '#667eea');
    }
  }, [theme, systemTheme]);

  const setThemeMode = (newTheme) => {
    setTheme(newTheme);
    localStorage.setItem('ssi-theme', newTheme);
  };

  const toggleTheme = () => {
    const effectiveTheme = theme === 'system' ? systemTheme : theme;
    setThemeMode(effectiveTheme === 'light' ? 'dark' : 'light');
  };

  const getEffectiveTheme = () => {
    return theme === 'system' ? systemTheme : theme;
  };

  const isDark = () => {
    return getEffectiveTheme() === 'dark';
  };

  const value = {
    theme,
    systemTheme,
    setTheme: setThemeMode,
    toggleTheme,
    getEffectiveTheme,
    isDark,
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
};
