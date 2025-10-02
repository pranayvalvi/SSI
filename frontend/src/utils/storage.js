// Local storage utilities with error handling

const STORAGE_KEYS = {
  AUTH_TOKEN: 'ssi_auth_token',
  USER_PREFERENCES: 'ssi_user_preferences',
  THEME: 'ssi_theme',
  WALLET_ADDRESS: 'ssi_wallet_address',
  RECENT_CREDENTIALS: 'ssi_recent_credentials',
  CACHE_PREFIX: 'ssi_cache_',
};

// Safe localStorage operations
const safeLocalStorage = {
  getItem: (key) => {
    try {
      return localStorage.getItem(key);
    } catch (error) {
      console.warn('localStorage getItem failed:', error);
      return null;
    }
  },
  
  setItem: (key, value) => {
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (error) {
      console.warn('localStorage setItem failed:', error);
      return false;
    }
  },
  
  removeItem: (key) => {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (error) {
      console.warn('localStorage removeItem failed:', error);
      return false;
    }
  },
  
  clear: () => {
    try {
      localStorage.clear();
      return true;
    } catch (error) {
      console.warn('localStorage clear failed:', error);
      return false;
    }
  }
};

// Authentication token management
export const getStoredToken = () => {
  return safeLocalStorage.getItem(STORAGE_KEYS.AUTH_TOKEN);
};

export const setStoredToken = (token) => {
  return safeLocalStorage.setItem(STORAGE_KEYS.AUTH_TOKEN, token);
};

export const removeStoredToken = () => {
  return safeLocalStorage.removeItem(STORAGE_KEYS.AUTH_TOKEN);
};

// User preferences
export const getUserPreferences = () => {
  try {
    const prefs = safeLocalStorage.getItem(STORAGE_KEYS.USER_PREFERENCES);
    return prefs ? JSON.parse(prefs) : {};
  } catch (error) {
    console.warn('Failed to parse user preferences:', error);
    return {};
  }
};

export const setUserPreferences = (preferences) => {
  try {
    const currentPrefs = getUserPreferences();
    const updatedPrefs = { ...currentPrefs, ...preferences };
    return safeLocalStorage.setItem(STORAGE_KEYS.USER_PREFERENCES, JSON.stringify(updatedPrefs));
  } catch (error) {
    console.warn('Failed to save user preferences:', error);
    return false;
  }
};

// Theme management
export const getStoredTheme = () => {
  return safeLocalStorage.getItem(STORAGE_KEYS.THEME) || 'system';
};

export const setStoredTheme = (theme) => {
  return safeLocalStorage.setItem(STORAGE_KEYS.THEME, theme);
};

// Wallet address
export const getStoredWalletAddress = () => {
  return safeLocalStorage.getItem(STORAGE_KEYS.WALLET_ADDRESS);
};

export const setStoredWalletAddress = (address) => {
  return safeLocalStorage.setItem(STORAGE_KEYS.WALLET_ADDRESS, address);
};

export const removeStoredWalletAddress = () => {
  return safeLocalStorage.removeItem(STORAGE_KEYS.WALLET_ADDRESS);
};

// Recent credentials
export const getRecentCredentials = () => {
  try {
    const recent = safeLocalStorage.getItem(STORAGE_KEYS.RECENT_CREDENTIALS);
    return recent ? JSON.parse(recent) : [];
  } catch (error) {
    console.warn('Failed to parse recent credentials:', error);
    return [];
  }
};

export const addRecentCredential = (credential) => {
  try {
    const recent = getRecentCredentials();
    const updated = [credential, ...recent.filter(c => c.id !== credential.id)].slice(0, 10); // Keep last 10
    return safeLocalStorage.setItem(STORAGE_KEYS.RECENT_CREDENTIALS, JSON.stringify(updated));
  } catch (error) {
    console.warn('Failed to add recent credential:', error);
    return false;
  }
};

// Generic cache management
export const getCacheItem = (key, maxAge = 3600000) => { // Default 1 hour
  try {
    const cacheKey = STORAGE_KEYS.CACHE_PREFIX + key;
    const cached = safeLocalStorage.getItem(cacheKey);
    
    if (!cached) return null;
    
    const { data, timestamp } = JSON.parse(cached);
    const age = Date.now() - timestamp;
    
    if (age > maxAge) {
      safeLocalStorage.removeItem(cacheKey);
      return null;
    }
    
    return data;
  } catch (error) {
    console.warn('Failed to get cache item:', error);
    return null;
  }
};

export const setCacheItem = (key, data) => {
  try {
    const cacheKey = STORAGE_KEYS.CACHE_PREFIX + key;
    const cacheData = {
      data,
      timestamp: Date.now()
    };
    return safeLocalStorage.setItem(cacheKey, JSON.stringify(cacheData));
  } catch (error) {
    console.warn('Failed to set cache item:', error);
    return false;
  }
};

export const removeCacheItem = (key) => {
  const cacheKey = STORAGE_KEYS.CACHE_PREFIX + key;
  return safeLocalStorage.removeItem(cacheKey);
};

export const clearCache = () => {
  try {
    const keys = Object.keys(localStorage);
    const cacheKeys = keys.filter(key => key.startsWith(STORAGE_KEYS.CACHE_PREFIX));
    
    cacheKeys.forEach(key => {
      safeLocalStorage.removeItem(key);
    });
    
    return true;
  } catch (error) {
    console.warn('Failed to clear cache:', error);
    return false;
  }
};

// Clear all app data
export const clearAllAppData = () => {
  try {
    Object.values(STORAGE_KEYS).forEach(key => {
      if (key !== STORAGE_KEYS.CACHE_PREFIX) {
        safeLocalStorage.removeItem(key);
      }
    });
    
    clearCache();
    return true;
  } catch (error) {
    console.warn('Failed to clear app data:', error);
    return false;
  }
};

// Storage event listener for cross-tab synchronization
export const onStorageChange = (callback) => {
  const handleStorageChange = (event) => {
    if (event.key && Object.values(STORAGE_KEYS).some(key => event.key.includes(key))) {
      callback(event);
    }
  };
  
  window.addEventListener('storage', handleStorageChange);
  
  return () => {
    window.removeEventListener('storage', handleStorageChange);
  };
};

// Check if localStorage is available
export const isStorageAvailable = () => {
  try {
    const test = '__storage_test__';
    localStorage.setItem(test, test);
    localStorage.removeItem(test);
    return true;
  } catch (error) {
    return false;
  }
};

// Get storage usage info
export const getStorageInfo = () => {
  if (!isStorageAvailable()) {
    return { available: false };
  }
  
  try {
    let totalSize = 0;
    let appSize = 0;
    
    for (let key in localStorage) {
      if (localStorage.hasOwnProperty(key)) {
        const size = (localStorage[key].length + key.length) * 2; // Rough estimate in bytes
        totalSize += size;
        
        if (Object.values(STORAGE_KEYS).some(appKey => key.includes(appKey))) {
          appSize += size;
        }
      }
    }
    
    return {
      available: true,
      totalSize: totalSize,
      appSize: appSize,
      totalItems: Object.keys(localStorage).length,
      appItems: Object.keys(localStorage).filter(key => 
        Object.values(STORAGE_KEYS).some(appKey => key.includes(appKey))
      ).length
    };
  } catch (error) {
    console.warn('Failed to get storage info:', error);
    return { available: true, error: error.message };
  }
};

export default {
  getStoredToken,
  setStoredToken,
  removeStoredToken,
  getUserPreferences,
  setUserPreferences,
  getStoredTheme,
  setStoredTheme,
  getStoredWalletAddress,
  setStoredWalletAddress,
  removeStoredWalletAddress,
  getRecentCredentials,
  addRecentCredential,
  getCacheItem,
  setCacheItem,
  removeCacheItem,
  clearCache,
  clearAllAppData,
  onStorageChange,
  isStorageAvailable,
  getStorageInfo,
};
