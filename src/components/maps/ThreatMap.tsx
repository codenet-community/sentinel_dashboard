import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, Eye, EyeOff } from 'lucide-react';
import { ThreatData } from '@/hooks/useThreatData';
import { cn } from '@/lib/utils';

interface ThreatMapProps {
  threats: ThreatData[];
}

// A simple map visualization with threat points
const ThreatMap = ({ threats }: ThreatMapProps) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [showHeatmap, setShowHeatmap] = useState(true);
  const [animationFrame, setAnimationFrame] = useState<number | null>(null);
  
  // Draw function that renders the world map and attack points
  const draw = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // Set canvas dimensions to match its display size
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width;
    canvas.height = rect.height;
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw world map background (simplified)
    ctx.fillStyle = 'rgba(255, 255, 255, 0.03)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    // Draw grid lines
    ctx.strokeStyle = 'rgba(180, 180, 200, 0.1)';
    ctx.lineWidth = 1;
    
    // Vertical grid lines
    for (let i = 0; i <= canvas.width; i += 40) {
      ctx.beginPath();
      ctx.moveTo(i, 0);
      ctx.lineTo(i, canvas.height);
      ctx.stroke();
    }
    
    // Horizontal grid lines
    for (let i = 0; i <= canvas.height; i += 40) {
      ctx.beginPath();
      ctx.moveTo(0, i);
      ctx.lineTo(canvas.width, i);
      ctx.stroke();
    }
    
    // If no threat data, draw placeholder
    if (threats.length === 0) {
      ctx.fillStyle = 'rgba(100, 100, 100, 0.5)';
      ctx.font = '14px SF Pro Display, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No threat data available', canvas.width / 2, canvas.height / 2);
      return;
    }
    
    // Draw threat points
    threats.forEach((threat) => {
      if (!threat.coordinates) return;
      
      // Convert lat/lng to canvas x/y
      // This is a simple projection, not geographically accurate
      const x = ((threat.coordinates[1] + 180) / 360) * canvas.width;
      const y = ((90 - threat.coordinates[0]) / 180) * canvas.height;
      
      // Choose color based on severity
      let color;
      switch (threat.severity) {
        case 'High':
          color = 'rgba(255, 59, 48, 0.8)';
          break;
        case 'Medium':
          color = 'rgba(255, 149, 0, 0.8)';
          break;
        case 'Low':
          color = 'rgba(52, 199, 89, 0.8)';
          break;
        default:
          color = 'rgba(100, 100, 100, 0.8)';
      }
      
      // Draw point
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      
      // Draw pulse effect for active threats
      if (threat.status !== 'Mitigated') {
        ctx.beginPath();
        ctx.arc(x, y, 8, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.stroke();
        
        ctx.beginPath();
        const pulseSize = 12 + Math.sin(Date.now() / 500) * 4;
        ctx.arc(x, y, pulseSize, 0, Math.PI * 2);
        ctx.strokeStyle = color.replace('0.8', '0.3');
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      
      // Draw heatmap if enabled
      if (showHeatmap) {
        const gradient = ctx.createRadialGradient(x, y, 0, x, y, 40);
        gradient.addColorStop(0, color.replace('0.8', '0.3'));
        gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
        
        ctx.beginPath();
        ctx.arc(x, y, 40, 0, Math.PI * 2);
        ctx.fillStyle = gradient;
        ctx.fill();
      }
    });
    
    // Draw legend
    const legendY = canvas.height - 70;
    const legendX = 20;
    
    ctx.font = '12px SF Pro Display, sans-serif';
    ctx.fillStyle = 'rgba(180, 180, 200, 0.7)';
    ctx.textAlign = 'left';
    ctx.fillText('Threat Severity:', legendX, legendY);
    
    // High severity
    ctx.beginPath();
    ctx.arc(legendX + 10, legendY + 20, 4, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(255, 59, 48, 0.8)';
    ctx.fill();
    ctx.fillStyle = 'rgba(180, 180, 200, 0.7)';
    ctx.fillText('High', legendX + 20, legendY + 23);
    
    // Medium severity
    ctx.beginPath();
    ctx.arc(legendX + 60, legendY + 20, 4, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(255, 149, 0, 0.8)';
    ctx.fill();
    ctx.fillStyle = 'rgba(180, 180, 200, 0.7)';
    ctx.fillText('Medium', legendX + 70, legendY + 23);
    
    // Low severity
    ctx.beginPath();
    ctx.arc(legendX + 130, legendY + 20, 4, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(52, 199, 89, 0.8)';
    ctx.fill();
    ctx.fillStyle = 'rgba(180, 180, 200, 0.7)';
    ctx.fillText('Low', legendX + 140, legendY + 23);
    
    // Request next animation frame
    setAnimationFrame(requestAnimationFrame(draw));
  };
  
  useEffect(() => {
    // Start animation
    const frameId = requestAnimationFrame(draw);
    setAnimationFrame(frameId);
    
    // Clean up animation on unmount
    return () => {
      if (animationFrame) {
        cancelAnimationFrame(animationFrame);
      }
    };
  }, [threats, showHeatmap]);
  
  // Redraw on window resize
  useEffect(() => {
    const handleResize = () => {
      if (animationFrame) {
        cancelAnimationFrame(animationFrame);
      }
      requestAnimationFrame(draw);
    };
    
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);
  
  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-medium">Threat Map</h2>
        <button
          onClick={() => setShowHeatmap(!showHeatmap)}
          className="inline-flex items-center text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          {showHeatmap ? (
            <>
              <EyeOff className="h-3.5 w-3.5 mr-1" />
              Hide Heatmap
            </>
          ) : (
            <>
              <Eye className="h-3.5 w-3.5 mr-1" />
              Show Heatmap
            </>
          )}
        </button>
      </div>
      
      <div className="glass-card rounded-lg overflow-hidden flex-1 relative">
        <canvas 
          ref={canvasRef} 
          className="w-full h-full absolute inset-0 dark:bg-gray-900/50"
        />
        
        {threats.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <AlertTriangle className="mx-auto h-10 w-10 text-muted-foreground opacity-20" />
              <p className="mt-2 text-muted-foreground">No threat data available</p>
            </div>
          </div>
        )}
        
        <div className="absolute bottom-0 left-0 right-0 h-24 bg-gradient-to-t from-background/80 to-transparent pointer-events-none" />
      </div>
    </div>
  );
};

export default ThreatMap;
