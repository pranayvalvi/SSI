import React, { createContext, useContext, useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { authAPI } from '../services/api';
import { getStoredToken, setStoredToken, removeStoredToken } from '../utils/storage';

const AuthContext = createContext({});

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const [initializing, setInitializing] = useState(true);

  // Initialize auth state from stored token
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        const token = getStoredToken();
        if (token) {
          // Verify token with backend
          const response = await authAPI.verifyToken();
          if (response.success) {
            setUser(response.data.user);
            setIsAuthenticated(true);
          } else {
            // Token is invalid, remove it
            removeStoredToken();
          }
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        removeStoredToken();
      } finally {
        setLoading(false);
        setInitializing(false);
      }
    };

    initializeAuth();
  }, []);

  // Login function
  const login = async (credentials) => {
    try {
      setLoading(true);
      const response = await authAPI.login(credentials);
      
      if (response.success) {
        const { token, user: userData } = response.data;
        
        // Store token
        setStoredToken(token);
        
        // Update state
        setUser(userData);
        setIsAuthenticated(true);
        
        toast.success(`Welcome back, ${userData.username}!`);
        return { success: true, user: userData };
      } else {
        toast.error(response.error?.message || 'Login failed');
        return { success: false, error: response.error };
      }
    } catch (error) {
      console.error('Login error:', error);
      const errorMessage = error.response?.data?.error?.message || 'Login failed. Please try again.';
      toast.error(errorMessage);
      return { success: false, error: { message: errorMessage } };
    } finally {
      setLoading(false);
    }
  };

  // Register function
  const register = async (userData) => {
    try {
      setLoading(true);
      const response = await authAPI.register(userData);
      
      if (response.success) {
        toast.success('Registration successful! Please log in.');
        return { success: true };
      } else {
        toast.error(response.error?.message || 'Registration failed');
        return { success: false, error: response.error };
      }
    } catch (error) {
      console.error('Registration error:', error);
      const errorMessage = error.response?.data?.error?.message || 'Registration failed. Please try again.';
      toast.error(errorMessage);
      return { success: false, error: { message: errorMessage } };
    } finally {
      setLoading(false);
    }
  };

  // Logout function
  const logout = async () => {
    try {
      // Call logout API (for logging purposes)
      await authAPI.logout();
    } catch (error) {
      console.error('Logout API error:', error);
    } finally {
      // Clear local state regardless of API call result
      removeStoredToken();
      setUser(null);
      setIsAuthenticated(false);
      toast.success('Logged out successfully');
    }
  };

  // Update profile function
  const updateProfile = async (profileData) => {
    try {
      setLoading(true);
      const response = await authAPI.updateProfile(profileData);
      
      if (response.success) {
        setUser(response.data.user);
        toast.success('Profile updated successfully');
        return { success: true, user: response.data.user };
      } else {
        toast.error(response.error?.message || 'Profile update failed');
        return { success: false, error: response.error };
      }
    } catch (error) {
      console.error('Profile update error:', error);
      const errorMessage = error.response?.data?.error?.message || 'Profile update failed';
      toast.error(errorMessage);
      return { success: false, error: { message: errorMessage } };
    } finally {
      setLoading(false);
    }
  };

  // Change password function
  const changePassword = async (passwordData) => {
    try {
      setLoading(true);
      const response = await authAPI.changePassword(passwordData);
      
      if (response.success) {
        toast.success('Password changed successfully');
        return { success: true };
      } else {
        toast.error(response.error?.message || 'Password change failed');
        return { success: false, error: response.error };
      }
    } catch (error) {
      console.error('Password change error:', error);
      const errorMessage = error.response?.data?.error?.message || 'Password change failed';
      toast.error(errorMessage);
      return { success: false, error: { message: errorMessage } };
    } finally {
      setLoading(false);
    }
  };

  // Get fresh user profile
  const refreshProfile = async () => {
    try {
      const response = await authAPI.getProfile();
      if (response.success) {
        setUser(response.data.user);
        return response.data.user;
      }
    } catch (error) {
      console.error('Profile refresh error:', error);
    }
    return null;
  };

  // Check if user has specific role
  const hasRole = (role) => {
    if (!user) return false;
    if (Array.isArray(role)) {
      return role.includes(user.role);
    }
    return user.role === role;
  };

  // Check if user is issuer
  const isIssuer = () => {
    return hasRole(['issuer', 'admin']);
  };

  // Check if user is admin
  const isAdmin = () => {
    return hasRole('admin');
  };

  const value = {
    // State
    user,
    isAuthenticated,
    loading,
    initializing,
    
    // Actions
    login,
    register,
    logout,
    updateProfile,
    changePassword,
    refreshProfile,
    
    // Utilities
    hasRole,
    isIssuer,
    isAdmin,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
