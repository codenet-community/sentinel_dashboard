
/**
 * Utility functions for handling audio in the application
 */

/**
 * Plays an audio file with proper error handling
 * @param audioElement The HTML Audio element to play
 * @param volume Volume level (0-100)
 * @returns Promise that resolves when audio starts playing or rejects with error
 */
export const playAudio = (audioElement: HTMLAudioElement | null, volume: number): Promise<void> => {
  return new Promise((resolve, reject) => {
    if (!audioElement) {
      reject(new Error('Audio element not initialized'));
      return;
    }

    try {
      // Set volume (convert from 0-100 scale to 0-1)
      audioElement.volume = Math.max(0, Math.min(volume / 100, 1));
      
      // Reset playback position
      audioElement.currentTime = 0;
      
      // Play audio with proper error handling
      const playPromise = audioElement.play();
      
      if (playPromise !== undefined) {
        playPromise
          .then(() => {
            console.log('Audio playback started successfully');
            resolve();
          })
          .catch(error => {
            console.error('Audio playback failed:', error);
            
            // Handle specific error cases
            if (error.name === 'NotAllowedError') {
              console.warn('Audio playback was blocked by the browser. User interaction is required before audio can play.');
            } else if (error.name === 'NotSupportedError') {
              console.warn('The audio format is not supported by this browser.');
            }
            
            reject(error);
          });
      } else {
        resolve(); // Old browsers that don't return a promise
      }
    } catch (error) {
      console.error('Error playing audio:', error);
      reject(error);
    }
  });
};

/**
 * Initializes an audio element with proper error handling
 * @param audioUrl URL of the audio file to load
 * @returns The audio element or null if initialization failed
 */
export const initializeAudio = (audioUrl: string): HTMLAudioElement | null => {
  try {
    const audio = new Audio(audioUrl);
    audio.preload = 'auto';
    
    // Force a load attempt
    audio.load();
    
    return audio;
  } catch (error) {
    console.error('Error initializing audio:', error);
    return null;
  }
};
