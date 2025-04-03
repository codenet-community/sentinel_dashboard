
import { useEffect, useState, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, LineChart, Line, CartesianGrid, Legend } from 'recharts';
import { ThreatData } from '@/hooks/useThreatData';
import { format, subDays, startOfDay, endOfDay, isEqual } from 'date-fns';
import { AlertOctagon, TrendingUp } from 'lucide-react';

interface ThreatTrendsProps {
  threats: ThreatData[];
}

const ThreatTrends = ({ threats }: ThreatTrendsProps) => {
  const [dailyData, setDailyData] = useState<any[]>([]);
  const [typeData, setTypeData] = useState<any[]>([]);
  const previousThreatsRef = useRef<ThreatData[]>([]);
  
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
    // Only process data if threats actually changed or this is the first render
    if (!threats.length || (!hasThreatsChanged(previousThreatsRef.current, threats) && dailyData.length > 0)) {
      return;
    }
    
    // Update the ref with current threats
    previousThreatsRef.current = [...threats];
    
    // Generate data for daily trends (last 7 days)
    const last7Days = Array.from({ length: 7 }, (_, i) => {
      const date = subDays(new Date(), 6 - i);
      return {
        date: format(date, 'MM/dd'),
        high: 0,
        medium: 0,
        low: 0,
        total: 0,
        dayStart: startOfDay(date),
        dayEnd: endOfDay(date)
      };
    });
    
    // Count threats by day and severity
    threats.forEach(threat => {
      const threatDate = new Date(threat.timestamp);
      const dayIndex = last7Days.findIndex(day => 
        threatDate >= day.dayStart && threatDate <= day.dayEnd
      );
      
      if (dayIndex !== -1) {
        if (threat.severity === 'High') last7Days[dayIndex].high++;
        else if (threat.severity === 'Medium') last7Days[dayIndex].medium++;
        else if (threat.severity === 'Low') last7Days[dayIndex].low++;
        
        last7Days[dayIndex].total++;
      }
    });
    
    setDailyData(last7Days);
    
    // Aggregate threats by type
    const attackTypes: Record<string, number> = {};
    threats.forEach(threat => {
      if (!attackTypes[threat.attack_type]) {
        attackTypes[threat.attack_type] = 0;
      }
      attackTypes[threat.attack_type]++;
    });
    
    // Convert to array and sort by count
    const typeArray = Object.entries(attackTypes).map(([name, value]) => ({ name, value }));
    typeArray.sort((a, b) => b.value - a.value);
    
    setTypeData(typeArray.slice(0, 5)); // Top 5 attack types
  }, [threats, dailyData.length]);
  
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="glass-card p-3 border border-border shadow-lg">
          <p className="text-sm font-medium mb-1">{label}</p>
          {payload.map((entry: any) => (
            <div key={entry.name} className="flex items-center justify-between text-xs py-0.5">
              <span className="flex items-center">
                <span className="h-2 w-2 rounded-full mr-1" style={{ backgroundColor: entry.color }}></span>
                {entry.name === 'total' ? 'Total' : entry.name}
              </span>
              <span className="font-mono">{entry.value}</span>
            </div>
          ))}
        </div>
      );
    }
    
    return null;
  };
  
  return (
    <div className="mt-6">
      <h2 className="text-lg font-medium mb-4 flex items-center">
        <TrendingUp className="h-5 w-5 mr-2 text-primary" />
        Threat Trends
      </h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium">Weekly Threat Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {dailyData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={dailyData}
                    margin={{ top: 20, right: 30, left: 0, bottom: 5 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      dataKey="date" 
                      tick={{ fontSize: 12 }}
                      axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                      tickLine={false}
                    />
                    <YAxis 
                      tick={{ fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Legend
                      verticalAlign="top"
                      height={36}
                      iconSize={10}
                      iconType="circle"
                      wrapperStyle={{ fontSize: '12px' }}
                    />
                    <Line type="monotone" dataKey="total" name="Total" stroke="#9E86FF" strokeWidth={2} dot={{ r: 3 }} activeDot={{ r: 6 }} />
                    <Line type="monotone" dataKey="high" name="High" stroke="#FF3B30" strokeWidth={1.5} dot={{ r: 2 }} />
                    <Line type="monotone" dataKey="medium" name="Medium" stroke="#FF9500" strokeWidth={1.5} dot={{ r: 2 }} />
                    <Line type="monotone" dataKey="low" name="Low" stroke="#34C759" strokeWidth={1.5} dot={{ r: 2 }} />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertOctagon className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">No data available</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
        
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base font-medium">Top Attack Types</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              {typeData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={typeData}
                    layout="vertical"
                    margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} stroke="rgba(255,255,255,0.1)" />
                    <XAxis 
                      type="number"
                      tick={{ fontSize: 12 }}
                      axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                      tickLine={false}
                    />
                    <YAxis 
                      dataKey="name" 
                      type="category" 
                      tick={{ fontSize: 12 }}
                      axisLine={false}
                      tickLine={false}
                      width={150}
                    />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar 
                      dataKey="value" 
                      name="Count" 
                      fill="#007AFF" 
                      radius={[0, 4, 4, 0]}
                      barSize={20}
                    />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
                  <AlertOctagon className="h-10 w-10 mb-2 opacity-20" />
                  <p className="text-sm">No data available</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default ThreatTrends;
