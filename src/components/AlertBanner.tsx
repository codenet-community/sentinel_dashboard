
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
      audioRef.current = new Audio('/alert.mp3');
    }
    
    // Set volume and play sound if enabled
    if (soundEnabled && audioRef.current) {
      audioRef.current.volume = soundVolume / 100;
      
      const playPromise = audioRef.current.play();
      setIsPlaying(true);
      
      // Handle play() promise rejection (browser policy may prevent autoplay)
      if (playPromise !== undefined) {
        playPromise
          .then(() => setIsPlaying(true))
          .catch(error => {
            console.error('Audio playback failed:', error);
            setIsPlaying(false);
          });
      }
    }
    
    // Auto-dismiss after 15 seconds (increased from 10)
    closeTimeoutRef.current = window.setTimeout(() => {
      onClose();
    }, 15000);
    
    return () => {
      if (closeTimeoutRef.current !== null) {
        window.clearTimeout(closeTimeoutRef.current);
      }
      
      // Stop audio on unmount
      if (audioRef.current && isPlaying) {
        audioRef.current.pause();
        audioRef.current.currentTime = 0;
        setIsPlaying(false);
      }
    };
  }, [onClose, soundEnabled, soundVolume]);
  
  return (
    <AnimatePresence>
      <motion.div 
        className="alert-banner mb-4"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
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
