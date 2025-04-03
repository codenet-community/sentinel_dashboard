
import { useEffect, useState, useRef } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from 'recharts';
import { ThreatData } from '@/hooks/useThreatData';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ArrowUpRight, BarChartIcon } from 'lucide-react';
import { format, subHours, isEqual } from 'date-fns';

interface ThreatChartProps {
  threats: ThreatData[];
}

const ThreatChart = ({ threats }: ThreatChartProps) => {
  const [chartData, setChartData] = useState<any[]>([]);
  const previousThreatsRef = useRef<ThreatData[]>([]);
  const initialRenderRef = useRef<boolean>(true);
  
  // Function to check if threats data has actually changed in a meaningful way
  const hasThreatsChanged = (oldThreats: ThreatData[], newThreats: ThreatData[]) => {
    if (oldThreats.length !== newThreats.length) return true;
    
    // Create a set of threat IDs for quick lookup
    const oldIds = new Set(oldThreats.map(t => t.id));
    const newIds = new Set(newThreats.map(t => t.id));
    
    // Check if any new IDs appeared
    for (const id of newIds) {
      if (!oldIds.has(id)) return true;
    }
    
    // Check if any IDs disappeared
    for (const id of oldIds) {
      if (!newIds.has(id)) return true;
    }
    
    return false;
  };
  
  useEffect(() => {
    // Skip processing if threats haven't changed and this isn't the first render
    if (!threats.length || 
        (!initialRenderRef.current && 
         !hasThreatsChanged(previousThreatsRef.current, threats) && 
         chartData.length > 0)) {
      return;
    }
    
    // Update the ref with current threats
    previousThreatsRef.current = [...threats];
    initialRenderRef.current = false;
    
    // Generate time slots for the last 12 hours
    const timeSlots = Array.from({ length: 12 }, (_, i) => {
      const date = subHours(new Date(), 11 - i);
      return {
        hour: format(date, 'HH:00'),
        high: 0,
        medium: 0,
        low: 0,
        timestamp: date,
      };
    });
    
    // Count threats by severity for each hour
    threats.forEach(threat => {
      const threatTime = new Date(threat.timestamp);
      const slotIndex = timeSlots.findIndex(slot => {
        const slotTime = slot.timestamp;
        const nextSlotTime = new Date(slotTime);
        nextSlotTime.setHours(slotTime.getHours() + 1);
        return threatTime >= slotTime && threatTime < nextSlotTime;
      });
      
      if (slotIndex !== -1) {
        if (threat.severity === 'High') timeSlots[slotIndex].high++;
        else if (threat.severity === 'Medium') timeSlots[slotIndex].medium++;
        else if (threat.severity === 'Low') timeSlots[slotIndex].low++;
      }
    });
    
    setChartData(timeSlots);
  }, [threats, chartData.length]);
  
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const total = payload.reduce((acc: number, item: any) => acc + item.value, 0);
      
      return (
        <div className="glass-card p-3 border border-border shadow-lg">
          <p className="text-sm font-medium mb-2">{label}</p>
          {payload.map((entry: any, index: number) => (
            <div key={`tooltip-${index}`} className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }}></span>
                {entry.name}
              </span>
              <span className="font-mono">{entry.value}</span>
            </div>
          ))}
          <div className="mt-2 pt-2 border-t border-border flex justify-between text-xs font-medium">
            <span>Total</span>
            <span>{total}</span>
          </div>
        </div>
      );
    }
    
    return null;
  };
  
  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg font-medium">Threat Activity</CardTitle>
          <button className="text-xs text-muted-foreground hover:text-foreground transition-colors flex items-center">
            <span>View Details</span>
            <ArrowUpRight className="ml-1 h-3 w-3" />
          </button>
        </div>
      </CardHeader>
      <CardContent>
        {chartData.length > 0 ? (
          <div className="h-[240px] mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={chartData}
                margin={{ top: 5, right: 5, left: -20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.1)" />
                <XAxis 
                  dataKey="hour" 
                  tick={{ fontSize: 10 }} 
                  axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                  tickLine={false}
                />
                <YAxis 
                  allowDecimals={false}
                  tick={{ fontSize: 10 }} 
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend 
                  align="right" 
                  verticalAlign="top"
                  iconSize={8}
                  iconType="circle"
                  wrapperStyle={{ fontSize: '10px', marginTop: '-10px' }}
                />
                <Bar dataKey="high" name="High" stackId="a" fill="#FF3B30" radius={[2, 2, 0, 0]} maxBarSize={30} />
                <Bar dataKey="medium" name="Medium" stackId="a" fill="#FF9500" radius={[2, 2, 0, 0]} maxBarSize={30} />
                <Bar dataKey="low" name="Low" stackId="a" fill="#34C759" radius={[2, 2, 0, 0]} maxBarSize={30} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="h-[240px] flex flex-col items-center justify-center text-muted-foreground">
            <BarChartIcon className="h-10 w-10 mb-2 opacity-20" />
            <p className="text-sm">No data available</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default ThreatChart;
