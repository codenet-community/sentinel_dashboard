
/**
 * Utility functions for safely handling browser storage operations
 */

/**
 * Safely retrieves a value from localStorage with type conversion
 * @param key The key to retrieve from localStorage
 * @param defaultValue The default value to return if retrieval fails
 * @returns The retrieved value or the default value
 */
export function getFromStorage<T>(key: string, defaultValue: T): T {
  try {
    const item = localStorage.getItem(key);
    if (item === null) return defaultValue;
    
    // Try to parse as JSON if it's not a string
    if (typeof defaultValue !== 'string') {
      try {
        return JSON.parse(item) as T;
      } catch {
        return defaultValue;
      }
    }
    
    // If default is string, return item directly
    return item as unknown as T;
  } catch (error) {
    console.error(`Error retrieving ${key} from localStorage:`, error);
    return defaultValue;
  }
}

/**
 * Safely stores a value in localStorage with type handling
 * @param key The key to use in localStorage
 * @param value The value to store
 * @returns true if successful, false if failed
 */
export function saveToStorage<T>(key: string, value: T): boolean {
  try {
    if (typeof value === 'string') {
      localStorage.setItem(key, value);
    } else {
      localStorage.setItem(key, JSON.stringify(value));
    }
    return true;
  } catch (error) {
    console.error(`Error saving ${key} to localStorage:`, error);
    return false;
  }
}

/**
 * Safely removes a key from localStorage
 * @param key The key to remove
 * @returns true if successful, false if failed
 */
export function removeFromStorage(key: string): boolean {
  try {
    localStorage.removeItem(key);
    return true;
  } catch (error) {
    console.error(`Error removing ${key} from localStorage:`, error);
    return false;
  }
}

/**
 * Safely checks if a key exists in localStorage
 * @param key The key to check
 * @returns true if key exists, false otherwise
 */
export function hasStorageKey(key: string): boolean {
  try {
    return localStorage.getItem(key) !== null;
  } catch (error) {
    console.error(`Error checking for ${key} in localStorage:`, error);
    return false;
  }
}
