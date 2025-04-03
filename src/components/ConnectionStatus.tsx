
import { useState, useEffect, useRef } from 'react';
import { Wifi, WifiOff, Clock, Signal, AlertTriangle, Loader2, Database } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';

interface ConnectionStatusProps {
  isConnected: boolean;
  lastUpdated: Date | null;
  isReconnecting?: boolean;
  reconnectAttempts?: number;
  usingFallbackData?: boolean;
}

const ConnectionStatus = ({ 
  isConnected, 
  lastUpdated, 
  isReconnecting = false,
  reconnectAttempts = 0,
  usingFallbackData = false
}: ConnectionStatusProps) => {
  const [timeAgo, setTimeAgo] = useState<string>('');
  const [staleData, setStaleData] = useState<boolean>(false);
  const staleWarningShownRef = useRef<boolean>(false);
  
  useEffect(() => {
    const updateTime = () => {
      if (lastUpdated) {
        try {
          setTimeAgo(formatDistanceToNow(lastUpdated, { addSuffix: true }));
          
          // Check if data is stale (older than 30 seconds) - only for real connections
          const now = new Date();
          const timeDiff = now.getTime() - lastUpdated.getTime();
          const isDataStale = isConnected && !usingFallbackData && timeDiff > 30000;
          
          // Only update staleData state if it's actually changing
          if (isDataStale !== staleData) {
            setStaleData(isDataStale);
          }
          
          // Show toast for stale data only once
          if (isDataStale && isConnected && !staleWarningShownRef.current) {
            toast.warning("Data hasn't updated recently. Possible connection issues.", {
              id: "stale-data-warning",
            });
            staleWarningShownRef.current = true;
          } else if (!isDataStale) {
            staleWarningShownRef.current = false;
          }
        } catch (error) {
          console.error("Error formatting time:", error);
        }
      }
    };
    
    updateTime();
    const interval = setInterval(updateTime, 5000);
    
    return () => clearInterval(interval);
  }, [lastUpdated, isConnected, staleData, usingFallbackData]);
  
  return (
    <div className="flex items-center justify-end space-x-1 text-xs">
      {isConnected ? (
        <div className={cn(
          "flex items-center transition-colors",
          usingFallbackData ? "text-yellow-500" : 
          staleData ? "text-yellow-500" : "text-green-500"
        )}>
          {isReconnecting ? (
            <>
              <Loader2 className="h-3 w-3 mr-1 animate-spin" />
              <span>Reconnecting{reconnectAttempts > 0 ? ` (attempt ${reconnectAttempts})` : ''}</span>
            </>
          ) : usingFallbackData ? (
            <>
              <Database className="h-3 w-3 mr-1" />
              <span>Using sample data</span>
            </>
          ) : staleData ? (
            <>
              <AlertTriangle className="h-3 w-3 mr-1" />
              <span>Potentially stale data</span>
            </>
          ) : (
            <>
              <Signal className="h-3 w-3 mr-1 animate-pulse" />
              <span>Connected</span>
            </>
          )}
          {lastUpdated && (
            <div className={cn(
              "flex items-center ml-3",
              usingFallbackData ? "text-yellow-500/70" : 
              staleData ? "text-yellow-500/70" : "text-muted-foreground"
            )}>
              <Clock className="h-3 w-3 mr-1" />
              <span>Last updated {timeAgo}</span>
            </div>
          )}
        </div>
      ) : (
        <div className="flex items-center text-red-500">
          <WifiOff className="h-3 w-3 mr-1" />
          <span>Disconnected</span>
          {isReconnecting && (
            <span className="ml-1">- Attempting to reconnect{reconnectAttempts > 0 ? ` (${reconnectAttempts})` : ''}</span>
          )}
        </div>
      )}
    </div>
  );
};

export default ConnectionStatus;
