import { useEffect, useRef, useState } from 'react';
import { X, AlertTriangle, Volume2, VolumeX, ShieldAlert } from 'lucide-react';
import { ThreatData } from '@/hooks/useThreatData';
import { Button } from '@/components/ui/button';
import { motion, AnimatePresence } from 'framer-motion';

interface AlertBannerProps {
  threat: ThreatData;
  onClose: () => void;
  soundEnabled: boolean;
  soundVolume: number;
  toggleSound?: () => void;
}

const AlertBanner = ({ 
  threat, 
  onClose, 
  soundEnabled, 
  soundVolume,
  toggleSound 
}: AlertBannerProps) => {
  const closeTimeoutRef = useRef<number | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  
  useEffect(() => {
    // Initialize audio element
    if (!audioRef.current) {
      try {
        audioRef.current = new Audio('/alert.mp3');
        // Preload the audio
        audioRef.current.load();
        console.log('Alert sound initialized');
      } catch (error) {
        console.error('Error initializing alert sound:', error);
      }
    }
    
    // Set volume and play sound if enabled
    if (soundEnabled && audioRef.current) {
      try {
        audioRef.current.volume = soundVolume / 100;
        audioRef.current.currentTime = 0;
        
        const playPromise = audioRef.current.play();
        setIsPlaying(true);
        
        // Handle play() promise rejection (browser policy may prevent autoplay)
        if (playPromise !== undefined) {
          playPromise
            .then(() => {
              console.log('Alert sound playing successfully');
              setIsPlaying(true);
            })
            .catch(error => {
              console.error('Audio playback failed:', error);
              setIsPlaying(false);
            });
        }
      } catch (err) {
        console.error('Error playing alert sound:', err);
      }
    }
    
    // Auto-dismiss after 15 seconds
    closeTimeoutRef.current = window.setTimeout(() => {
      onClose();
    }, 15000);
    
    return () => {
      if (closeTimeoutRef.current !== null) {
        window.clearTimeout(closeTimeoutRef.current);
      }
      
      // Stop audio on unmount
      if (audioRef.current && isPlaying) {
        try {
          audioRef.current.pause();
          audioRef.current.currentTime = 0;
          setIsPlaying(false);
        } catch (err) {
          console.error('Error stopping alert sound:', err);
        }
      }
    };
  }, [onClose, soundEnabled, soundVolume]);
  
  return (
    <AnimatePresence>
      <motion.div 
        className="alert-banner fixed bottom-6 left-1/2 transform -translate-x-1/2 bg-background/90 backdrop-blur-sm border border-border/50 rounded-lg shadow-lg py-3 px-4 w-full max-w-md z-50 flex justify-between items-center"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 20 }}
        transition={{ duration: 0.3 }}
      >
        <div className="flex items-center gap-3">
          <div className="relative">
            <ShieldAlert className="h-6 w-6 text-destructive" />
            <span className="absolute -top-1 -right-1 flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-destructive opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-destructive"></span>
            </span>
          </div>
          <div>
            <h3 className="font-medium">
              {threat.attack_type}{' '}
              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-destructive/10 text-destructive ml-2">
                High Severity
              </span>
            </h3>
            <p className="text-sm text-muted-foreground">
              Threat detected from <span className="font-mono">{threat.ip}</span> targeting <span className="font-mono">{threat.details.url_path}</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 hover:bg-muted/50"
            onClick={toggleSound}
          >
            {soundEnabled ? (
              <Volume2 className="h-4 w-4 text-muted-foreground" />
            ) : (
              <VolumeX className="h-4 w-4 text-muted-foreground" />
            )}
          </Button>
          <Button 
            variant="ghost" 
            size="icon" 
            className="h-6 w-6 hover:bg-destructive/10" 
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </motion.div>
    </AnimatePresence>
  );
};

export default AlertBanner;
