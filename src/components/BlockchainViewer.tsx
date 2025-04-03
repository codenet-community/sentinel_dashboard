
import { useEffect, useState } from 'react';
import { Database, Lock, Hash, Clock, FileText, ChevronDown, ChevronUp, Shield, HistoryIcon, KeyRound, ServerIcon } from 'lucide-react';
import { BlockchainData } from '@/hooks/useThreatData';
import { format, formatDistanceToNow } from 'date-fns';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { motion, AnimatePresence } from 'framer-motion';
import { ScrollArea } from '@/components/ui/scroll-area';

interface BlockchainViewerProps {
  data: BlockchainData | null;
}

const shortenHash = (hash: string) => {
  if (!hash) return '';
  return `${hash.substring(0, 8)}...${hash.substring(hash.length - 8)}`;
};

const BlockchainBlock = ({ 
  block, 
  index, 
  isLatest,
  totalBlocks
}: { 
  block: any; 
  index: number; 
  isLatest: boolean;
  totalBlocks: number;
}) => {
  const [expanded, setExpanded] = useState(isLatest);
  const blockTime = new Date(block.timestamp);
  const timeAgo = formatDistanceToNow(blockTime, { addSuffix: true });
  
  // Determine block type and icon
  const blockType = block.data?.type || 'transaction';
  const blockTypeClass = {
    'genesis': 'text-blue-500',
    'attack': 'text-red-500',
    'mitigation': 'text-green-500',
    'transaction': 'text-yellow-500'
  }[blockType] || 'text-blue-500';
  
  const BlockIcon = () => {
    switch (blockType) {
      case 'genesis':
        return <KeyRound className={`h-4 w-4 ${blockTypeClass} mr-2`} />;
      case 'attack':
        return <Shield className={`h-4 w-4 ${blockTypeClass} mr-2`} />;
      case 'mitigation':
        return <Lock className={`h-4 w-4 ${blockTypeClass} mr-2`} />;
      default:
        return <ServerIcon className={`h-4 w-4 ${blockTypeClass} mr-2`} />;
    }
  };
  
  return (
    <motion.div 
      className={cn(
        "blockchain-block mb-6 last:mb-0",
        isLatest && "border-primary/30"
      )}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ 
        duration: 0.5,
        delay: index * 0.1,
        ease: "easeOut"
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center">
          <BlockIcon />
          <span className="text-sm font-medium">
            {index === 0 ? 'Genesis Block' : `Block ${totalBlocks - index}`}
          </span>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-xs text-muted-foreground">{timeAgo}</span>
          {isLatest && (
            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-primary/10 text-primary animate-pulse-subtle">
              Latest
            </span>
          )}
        </div>
      </div>
      
      <div className="space-y-1.5 text-xs">
        <div className="flex items-center bg-primary/5 rounded-md px-2 py-1.5">
          <Hash className="h-3.5 w-3.5 mr-1.5 text-primary/70" />
          <span className="font-mono text-primary/90">{shortenHash(block.hash)}</span>
        </div>
        
        <div className="flex items-center justify-between text-muted-foreground py-1">
          <div className="flex items-center">
            <Clock className="h-3.5 w-3.5 mr-1.5" />
            <span>{format(blockTime, 'MMM dd, HH:mm:ss')}</span>
          </div>
          <div className="px-1.5 py-0.5 rounded-full text-xs bg-muted/50">
            {blockType}
          </div>
        </div>
        
        <AnimatePresence>
          {expanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="overflow-hidden pt-2"
            >
              <div className="space-y-1.5 bg-muted/30 p-2 rounded-md border border-border/50">
                <div className="flex items-start text-muted-foreground">
                  <FileText className="h-3.5 w-3.5 mr-1.5 mt-0.5" />
                  <div className="font-mono overflow-hidden w-full">
                    <ScrollArea className="h-[120px] w-full rounded-md">
                      <pre className="text-xs whitespace-pre-wrap break-words p-1">
                        {JSON.stringify(block.data, null, 2)}
                      </pre>
                    </ScrollArea>
                  </div>
                </div>
                
                {index > 0 && (
                  <div className="flex items-center text-muted-foreground mt-1 pt-1 border-t border-border/30">
                    <Hash className="h-3.5 w-3.5 mr-1.5" />
                    <span className="text-xs">Prev: </span>
                    <span className="font-mono ml-1">{shortenHash(block.previous_hash)}</span>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      
      <button 
        onClick={() => setExpanded(!expanded)}
        className="mt-2 text-xs text-primary hover:text-primary/80 transition-colors flex items-center"
      >
        {expanded ? (
          <>
            <ChevronUp className="h-3 w-3 mr-1" />
            Hide details
          </>
        ) : (
          <>
            <ChevronDown className="h-3 w-3 mr-1" />
            View details
          </>
        )}
      </button>
      
      <div className="blockchain-connection"></div>
    </motion.div>
  );
};

const BlockchainViewer = ({ data }: BlockchainViewerProps) => {
  const [visibleBlocks, setVisibleBlocks] = useState(3);
  
  useEffect(() => {
    // Reset visible blocks when data changes
    if (data) {
      setVisibleBlocks(Math.min(3, data.chain.length));
    }
  }, [data]);
  
  if (!data || data.chain.length === 0) {
    return (
      <Card className="animate-fade-in h-full">
        <CardHeader>
          <CardTitle className="flex items-center">
            <Shield className="h-5 w-5 text-primary mr-2" />
            Blockchain Ledger
          </CardTitle>
        </CardHeader>
        <CardContent className="h-[calc(100%-60px)] flex flex-col items-center justify-center">
          <HistoryIcon className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4 animate-pulse" />
          <p className="text-muted-foreground text-center">No blockchain data available</p>
          <p className="text-xs text-muted-foreground mt-1 text-center">
            Connect to blockchain source to view immutable threat records
          </p>
        </CardContent>
      </Card>
    );
  }
  
  const displayedBlocks = data.chain.slice(0, visibleBlocks).reverse();
  const hasMoreBlocks = data.chain.length > visibleBlocks;
  
  return (
    <Card className="animate-fade-in h-full">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center">
          <HistoryIcon className="h-5 w-5 text-primary mr-2" />
          Blockchain Ledger
          <span className="ml-auto text-xs text-muted-foreground bg-muted/50 px-2 py-0.5 rounded-full">
            {data.chain.length} blocks
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="overflow-y-auto" style={{ height: 'calc(100% - 60px)' }}>
        <div className="mb-2">
          <p className="text-sm text-muted-foreground">
            Immutable record of security events verified by blockchain
          </p>
        </div>
        
        <div className="space-y-6 mt-4 relative blockchain-container">
          {displayedBlocks.map((block, index) => (
            <BlockchainBlock 
              key={block.hash} 
              block={block} 
              index={index} 
              isLatest={index === 0}
              totalBlocks={data.chain.length - 1}
            />
          ))}
          
          {hasMoreBlocks && (
            <div className="mt-4 text-center">
              <button 
                onClick={() => setVisibleBlocks(prev => Math.min(prev + 3, data.chain.length))}
                className="text-sm bg-primary/10 hover:bg-primary/20 text-primary px-4 py-2 rounded-md transition-colors"
              >
                Load more blocks ({data.chain.length - visibleBlocks} remaining)
              </button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default BlockchainViewer;
