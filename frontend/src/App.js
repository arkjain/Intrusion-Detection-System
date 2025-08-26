import React, { useState, useEffect, useRef } from "react";
import "./App.css";
import axios from "axios";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;
const WS_URL = `${BACKEND_URL.replace('https://', 'wss://').replace('http://', 'ws://')}/ws`;

const ThreatDashboard = () => {
  const [networkEvents, setNetworkEvents] = useState([]);
  const [threatAlerts, setThreatAlerts] = useState([]);
  const [statistics, setStatistics] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard');
  const wsRef = useRef(null);

  // WebSocket connection for real-time updates
  useEffect(() => {
    const connectWebSocket = () => {
      try {
        wsRef.current = new WebSocket(WS_URL);
        
        wsRef.current.onopen = () => {
          setIsConnected(true);
          console.log('WebSocket connected');
        };
        
        wsRef.current.onmessage = (event) => {
          const message = JSON.parse(event.data);
          
          if (message.type === 'network_event') {
            setNetworkEvents(prev => [message.data, ...prev.slice(0, 99)]); // Keep last 100 events
          } else if (message.type === 'threat_alert') {
            setThreatAlerts(prev => [message.data, ...prev.slice(0, 49)]); // Keep last 50 alerts
            // Show notification for new threats
            showThreatNotification(message.data);
          }
        };
        
        wsRef.current.onclose = () => {
          setIsConnected(false);
          console.log('WebSocket disconnected');
          // Attempt to reconnect after 3 seconds
          setTimeout(connectWebSocket, 3000);
        };
        
        wsRef.current.onerror = (error) => {
          console.error('WebSocket error:', error);
          setIsConnected(false);
        };
      } catch (error) {
        console.error('Failed to connect WebSocket:', error);
        setTimeout(connectWebSocket, 3000);
      }
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Fetch initial data
  useEffect(() => {
    fetchNetworkEvents();
    fetchThreatAlerts();
    fetchStatistics();
    
    // Refresh statistics every 10 seconds
    const statsInterval = setInterval(fetchStatistics, 10000);
    
    return () => clearInterval(statsInterval);
  }, []);

  const fetchNetworkEvents = async () => {
    try {
      const response = await axios.get(`${API}/events?limit=100`);
      setNetworkEvents(response.data);
    } catch (error) {
      console.error('Error fetching network events:', error);
    }
  };

  const fetchThreatAlerts = async () => {
    try {
      const response = await axios.get(`${API}/alerts?limit=50`);
      setThreatAlerts(response.data);
    } catch (error) {
      console.error('Error fetching threat alerts:', error);
    }
  };

  const fetchStatistics = async () => {
    try {
      const response = await axios.get(`${API}/statistics`);
      setStatistics(response.data);
    } catch (error) {
      console.error('Error fetching statistics:', error);
    }
  };

  const resolveAlert = async (alertId) => {
    try {
      await axios.post(`${API}/alerts/${alertId}/resolve`);
      setThreatAlerts(prev => 
        prev.map(alert => 
          alert.id === alertId ? { ...alert, resolved: true } : alert
        )
      );
    } catch (error) {
      console.error('Error resolving alert:', error);
    }
  };

  const showThreatNotification = (threat) => {
    // Simple browser notification (in production, use a proper notification library)
    if (Notification.permission === "granted") {
      new Notification(`🚨 ${threat.severity.toUpperCase()} Threat Detected`, {
        body: threat.description,
        icon: "/favicon.ico"
      });
    }
  };

  // Request notification permission
  useEffect(() => {
    if (Notification.permission === "default") {
      Notification.requestPermission();
    }
  }, []);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getConnectionStatusColor = (status) => {
    switch (status) {
      case 'allowed': return 'text-green-600 bg-green-100';
      case 'blocked': return 'text-red-600 bg-red-100';
      case 'suspicious': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const formatTimestamp = (timestamp) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 shadow-lg border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <h1 className="text-2xl font-bold text-blue-400">🛡️ Intrusion Detection System</h1>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`flex items-center ${isConnected ? 'text-green-400' : 'text-red-400'}`}>
                <div className={`w-3 h-3 rounded-full mr-2 ${isConnected ? 'bg-green-400' : 'bg-red-400'}`}></div>
                <span className="text-sm">{isConnected ? 'Connected' : 'Disconnected'}</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex space-x-8">
            {['dashboard', 'events', 'alerts'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`py-4 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab
                    ? 'border-blue-400 text-blue-400'
                    : 'border-transparent text-gray-400 hover:text-white hover:border-gray-300'
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {activeTab === 'dashboard' && (
          <div className="px-4 py-6 sm:px-0">
            <div className="mb-8">
              <h2 className="text-3xl font-bold text-white mb-6">Security Dashboard</h2>
              
              {/* Statistics Cards */}
              {statistics && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                  <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <div className="w-8 h-8 bg-blue-500 rounded-lg flex items-center justify-center">
                          <span className="text-white font-bold">📊</span>
                        </div>
                      </div>
                      <div className="ml-5 w-0 flex-1">
                        <dl>
                          <dt className="text-sm font-medium text-gray-400 truncate">Total Connections</dt>
                          <dd className="text-lg font-medium text-white">{statistics.total_connections}</dd>
                        </dl>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <div className="w-8 h-8 bg-red-500 rounded-lg flex items-center justify-center">
                          <span className="text-white font-bold">🚫</span>
                        </div>
                      </div>
                      <div className="ml-5 w-0 flex-1">
                        <dl>
                          <dt className="text-sm font-medium text-gray-400 truncate">Blocked Connections</dt>
                          <dd className="text-lg font-medium text-white">{statistics.blocked_connections}</dd>
                        </dl>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <div className="w-8 h-8 bg-yellow-500 rounded-lg flex items-center justify-center">
                          <span className="text-white font-bold">⚠️</span>
                        </div>
                      </div>
                      <div className="ml-5 w-0 flex-1">
                        <dl>
                          <dt className="text-sm font-medium text-gray-400 truncate">Active Threats</dt>
                          <dd className="text-lg font-medium text-white">{statistics.total_threats}</dd>
                        </dl>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                    <div className="flex items-center">
                      <div className="flex-shrink-0">
                        <div className="w-8 h-8 bg-green-500 rounded-lg flex items-center justify-center">
                          <span className="text-white font-bold">📈</span>
                        </div>
                      </div>
                      <div className="ml-5 w-0 flex-1">
                        <dl>
                          <dt className="text-sm font-medium text-gray-400 truncate">Bandwidth Usage</dt>
                          <dd className="text-lg font-medium text-white">{statistics.bandwidth_usage.toFixed(1)}%</dd>
                        </dl>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Recent Alerts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                  <h3 className="text-lg font-medium text-white mb-4">Recent Threats</h3>
                  <div className="space-y-3">
                    {threatAlerts.slice(0, 5).map((alert) => (
                      <div key={alert.id} className="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <span className={`px-2 py-1 text-xs font-semibold rounded-full ${getSeverityColor(alert.severity)}`}>
                              {alert.severity}
                            </span>
                            <span className="text-sm text-gray-300">{alert.threat_type}</span>
                          </div>
                          <p className="text-sm text-white mt-1">{alert.source_ip}</p>
                          <p className="text-xs text-gray-400">{formatTimestamp(alert.timestamp)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                  <h3 className="text-lg font-medium text-white mb-4">Top Source IPs</h3>
                  <div className="space-y-3">
                    {statistics && statistics.top_source_ips.slice(0, 5).map((ipData, index) => (
                      <div key={ipData.ip} className="flex items-center justify-between p-3 bg-gray-700 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <span className="flex items-center justify-center w-8 h-8 bg-blue-600 rounded-full text-white font-bold text-sm">
                            {index + 1}
                          </span>
                          <div>
                            <p className="text-sm font-medium text-white">{ipData.ip}</p>
                            <p className="text-xs text-gray-400">{ipData.count} connections</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'events' && (
          <div className="px-4 py-6 sm:px-0">
            <div className="mb-6">
              <h2 className="text-2xl font-bold text-white">Network Events</h2>
              <p className="text-gray-400">Real-time network traffic monitoring</p>
            </div>
            
            <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-700">
                  <thead className="bg-gray-700">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Timestamp
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Source IP
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Destination
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Protocol
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                        Size
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-gray-800 divide-y divide-gray-700">
                    {networkEvents.map((event) => (
                      <tr key={event.id} className="hover:bg-gray-700">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                          {formatTimestamp(event.timestamp)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                          {event.source_ip}:{event.source_port}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                          {event.dest_ip}:{event.dest_port}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                          {event.protocol}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${getConnectionStatusColor(event.connection_status)}`}>
                            {event.connection_status}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                          {event.packet_size}B
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'alerts' && (
          <div className="px-4 py-6 sm:px-0">
            <div className="mb-6">
              <h2 className="text-2xl font-bold text-white">Threat Alerts</h2>
              <p className="text-gray-400">Security incidents and threat detections</p>
            </div>
            
            <div className="space-y-4">
              {threatAlerts.map((alert) => (
                <div key={alert.id} className={`bg-gray-800 rounded-lg p-6 border border-gray-700 ${alert.resolved ? 'opacity-50' : ''}`}>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className={`px-3 py-1 text-sm font-semibold rounded-full ${getSeverityColor(alert.severity)}`}>
                          {alert.severity.toUpperCase()}
                        </span>
                        <span className="text-lg font-medium text-white">{alert.threat_type.replace('_', ' ').toUpperCase()}</span>
                        {alert.resolved && (
                          <span className="px-2 py-1 text-xs bg-green-600 text-white rounded-full">RESOLVED</span>
                        )}
                      </div>
                      
                      <p className="text-gray-300 mb-3">{alert.description}</p>
                      
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <span className="text-gray-400">Source IP:</span>
                          <span className="text-white ml-2">{alert.source_ip}</span>
                        </div>
                        <div>
                          <span className="text-gray-400">Destination:</span>
                          <span className="text-white ml-2">{alert.dest_ip}</span>
                        </div>
                        <div>
                          <span className="text-gray-400">Confidence:</span>
                          <span className="text-white ml-2">{(alert.confidence_score * 100).toFixed(1)}%</span>
                        </div>
                        <div>
                          <span className="text-gray-400">Time:</span>
                          <span className="text-white ml-2">{formatTimestamp(alert.timestamp)}</span>
                        </div>
                      </div>
                      
                      {alert.signature_matched && (
                        <div className="mt-3 p-2 bg-gray-700 rounded text-sm">
                          <span className="text-gray-400">Pattern matched:</span>
                          <code className="text-yellow-400 ml-2">{alert.signature_matched}</code>
                        </div>
                      )}
                    </div>
                    
                    <div className="ml-4">
                      {!alert.resolved && (
                        <button
                          onClick={() => resolveAlert(alert.id)}
                          className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                        >
                          Resolve
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <ThreatDashboard />
    </div>
  );
}

export default App;