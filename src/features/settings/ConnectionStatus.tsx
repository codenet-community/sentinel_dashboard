
import { Server, Wifi, WifiOff, Shield, Clock, RefreshCw } from 'lucide-react';
import { format } from 'date-fns';
import { cn } from '@/lib/utils';

interface ConnectionStatusProps {
  isConnected: boolean;
  lastUpdated: Date | null;
  isReconnecting: boolean;
  reconnectAttempts: number;
  usingFallbackData: boolean;
  apiConnected: boolean;
  blockchainConnected: boolean;
}

export const ConnectionStatus = ({
  isConnected,
  lastUpdated,
  isReconnecting,
  reconnectAttempts,
  usingFallbackData,
  apiConnected,
  blockchainConnected
}: ConnectionStatusProps) => {
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs bg-muted/50 rounded-md px-3 py-2">
      <div className="flex items-center">
        {isConnected ? (
          <Wifi className="h-3.5 w-3.5 text-green-500 mr-1.5" />
        ) : (
          <WifiOff className="h-3.5 w-3.5 text-red-500 mr-1.5" />
        )}
        <span className={cn("font-medium", isConnected ? "text-green-500" : "text-red-500")}>
          {isConnected ? "Connected" : "Disconnected"}
        </span>
      </div>
      
      <div className="mx-2 h-3 w-px bg-border" aria-hidden="true" />
      
      <div className="flex items-center">
        <Server className={`h-3.5 w-3.5 mr-1.5 ${apiConnected ? "text-green-500" : "text-red-500"}`} />
        <span className={cn("font-medium", apiConnected ? "text-green-500" : "text-red-500")}>
          Threat API: {apiConnected ? "Connected" : "Disconnected"}
        </span>
      </div>
      
      <div className="mx-2 h-3 w-px bg-border" aria-hidden="true" />
      
      <div className="flex items-center">
        <Shield className={`h-3.5 w-3.5 mr-1.5 ${blockchainConnected ? "text-green-500" : "text-red-500"}`} />
        <span className={cn("font-medium", blockchainConnected ? "text-green-500" : "text-red-500")}>
          Blockchain API: {blockchainConnected ? "Connected" : "Disconnected"}
        </span>
      </div>
      
      {lastUpdated && (
        <>
          <div className="mx-2 h-3 w-px bg-border" aria-hidden="true" />
          <div className="flex items-center text-muted-foreground">
            <Clock className="h-3 w-3 mr-1" />
            <span>Last updated: {format(lastUpdated, 'MMM dd, HH:mm:ss')}</span>
          </div>
        </>
      )}
      
      {isReconnecting && (
        <>
          <div className="mx-2 h-3 w-px bg-border" aria-hidden="true" />
          <div className="flex items-center text-orange-500">
            <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
            <span>Reconnecting (attempt {reconnectAttempts})</span>
          </div>
        </>
      )}
      
      {usingFallbackData && (
        <>
          <div className="mx-2 h-3 w-px bg-border" aria-hidden="true" />
          <div className="flex items-center text-blue-500">
            <span>Using sample data</span>
          </div>
        </>
      )}
    </div>
  );
};

export default ConnectionStatus;
