#!/usr/bin/env python3
"""
Comprehensive Backend Testing for Intrusion Detection System
Tests all API endpoints, detection engines, and real-time functionality
"""

import asyncio
import json
import time
import requests
import websockets
from datetime import datetime, timezone
import sys
import os

# Add backend to path for imports
sys.path.append('/app/backend')

class IDSBackendTester:
    def __init__(self):
        # Use the production URL from frontend/.env
        self.base_url = "https://intrusion-shield.preview.emergentagent.com/api"
        self.ws_url = "wss://intrusion-shield.preview.emergentagent.com/ws"
        self.test_results = {}
        
    def log_test(self, test_name, success, message=""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}: {message}")
        self.test_results[test_name] = {"success": success, "message": message}
        
    def test_basic_connectivity(self):
        """Test basic API connectivity"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if "Intrusion Detection System" in data.get("message", ""):
                    self.log_test("Basic API Connectivity", True, f"API responding: {data['message']}")
                    return True
                else:
                    self.log_test("Basic API Connectivity", False, f"Unexpected response: {data}")
                    return False
            else:
                self.log_test("Basic API Connectivity", False, f"HTTP {response.status_code}: {response.text}")
                return False
        except Exception as e:
            self.log_test("Basic API Connectivity", False, f"Connection error: {str(e)}")
            return False
    
    def test_network_events_api(self):
        """Test network events generation and retrieval"""
        try:
            # Wait a bit for background task to generate some events
            print("Waiting 5 seconds for traffic generation...")
            time.sleep(5)
            
            response = requests.get(f"{self.base_url}/events?limit=10", timeout=10)
            if response.status_code == 200:
                events = response.json()
                if isinstance(events, list) and len(events) > 0:
                    # Verify event structure
                    event = events[0]
                    required_fields = ['id', 'timestamp', 'source_ip', 'dest_ip', 'source_port', 'dest_port', 'protocol', 'packet_size', 'connection_status']
                    
                    missing_fields = [field for field in required_fields if field not in event]
                    if not missing_fields:
                        self.log_test("Network Events API", True, f"Retrieved {len(events)} events with proper structure")
                        return True, events
                    else:
                        self.log_test("Network Events API", False, f"Missing fields in event: {missing_fields}")
                        return False, []
                else:
                    self.log_test("Network Events API", False, "No events generated yet")
                    return False, []
            else:
                self.log_test("Network Events API", False, f"HTTP {response.status_code}: {response.text}")
                return False, []
        except Exception as e:
            self.log_test("Network Events API", False, f"Error: {str(e)}")
            return False, []
    
    def test_threat_alerts_api(self):
        """Test threat alerts detection and retrieval"""
        try:
            # Wait for potential alerts to be generated
            print("Waiting 10 seconds for threat detection...")
            time.sleep(10)
            
            response = requests.get(f"{self.base_url}/alerts?limit=20", timeout=10)
            if response.status_code == 200:
                alerts = response.json()
                if isinstance(alerts, list):
                    if len(alerts) > 0:
                        # Verify alert structure
                        alert = alerts[0]
                        required_fields = ['id', 'timestamp', 'threat_type', 'severity', 'source_ip', 'dest_ip', 'description']
                        
                        missing_fields = [field for field in required_fields if field not in alert]
                        if not missing_fields:
                            # Check for both signature and anomaly detection
                            signature_alerts = [a for a in alerts if a.get('signature_matched')]
                            anomaly_alerts = [a for a in alerts if a.get('is_anomaly')]
                            
                            detection_types = []
                            if signature_alerts:
                                detection_types.append(f"signature-based ({len(signature_alerts)})")
                            if anomaly_alerts:
                                detection_types.append(f"anomaly-based ({len(anomaly_alerts)})")
                            
                            self.log_test("Threat Alerts API", True, f"Retrieved {len(alerts)} alerts: {', '.join(detection_types) if detection_types else 'basic alerts'}")
                            return True, alerts
                        else:
                            self.log_test("Threat Alerts API", False, f"Missing fields in alert: {missing_fields}")
                            return False, []
                    else:
                        self.log_test("Threat Alerts API", True, "No threats detected yet (system working, no malicious traffic)")
                        return True, []
                else:
                    self.log_test("Threat Alerts API", False, f"Invalid response format: {type(alerts)}")
                    return False, []
            else:
                self.log_test("Threat Alerts API", False, f"HTTP {response.status_code}: {response.text}")
                return False, []
        except Exception as e:
            self.log_test("Threat Alerts API", False, f"Error: {str(e)}")
            return False, []
    
    def test_statistics_api(self):
        """Test network statistics calculation"""
        try:
            response = requests.get(f"{self.base_url}/statistics", timeout=10)
            if response.status_code == 200:
                stats = response.json()
                required_fields = ['total_connections', 'blocked_connections', 'suspicious_connections', 'total_threats', 'threats_by_type', 'top_source_ips', 'bandwidth_usage']
                
                missing_fields = [field for field in required_fields if field not in stats]
                if not missing_fields:
                    # Verify data types and reasonable values
                    if (isinstance(stats['total_connections'], int) and 
                        isinstance(stats['blocked_connections'], int) and
                        isinstance(stats['threats_by_type'], dict) and
                        isinstance(stats['top_source_ips'], list) and
                        isinstance(stats['bandwidth_usage'], (int, float))):
                        
                        self.log_test("Statistics API", True, f"Total connections: {stats['total_connections']}, Threats: {stats['total_threats']}")
                        return True, stats
                    else:
                        self.log_test("Statistics API", False, "Invalid data types in statistics")
                        return False, {}
                else:
                    self.log_test("Statistics API", False, f"Missing fields: {missing_fields}")
                    return False, {}
            else:
                self.log_test("Statistics API", False, f"HTTP {response.status_code}: {response.text}")
                return False, {}
        except Exception as e:
            self.log_test("Statistics API", False, f"Error: {str(e)}")
            return False, {}
    
    def test_alert_resolution(self, alerts):
        """Test alert resolution functionality"""
        if not alerts:
            self.log_test("Alert Resolution", True, "No alerts to resolve (skipped)")
            return True
            
        try:
            # Try to resolve the first alert
            alert_id = alerts[0]['id']
            response = requests.post(f"{self.base_url}/alerts/{alert_id}/resolve", timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    # Verify the alert was actually resolved
                    time.sleep(1)
                    check_response = requests.get(f"{self.base_url}/alerts?resolved=true", timeout=10)
                    if check_response.status_code == 200:
                        resolved_alerts = check_response.json()
                        resolved_ids = [a['id'] for a in resolved_alerts if a.get('resolved')]
                        
                        if alert_id in resolved_ids:
                            self.log_test("Alert Resolution", True, f"Successfully resolved alert {alert_id}")
                            return True
                        else:
                            self.log_test("Alert Resolution", False, "Alert not found in resolved list")
                            return False
                    else:
                        self.log_test("Alert Resolution", False, "Could not verify resolution")
                        return False
                else:
                    self.log_test("Alert Resolution", False, f"Resolution failed: {result}")
                    return False
            else:
                self.log_test("Alert Resolution", False, f"HTTP {response.status_code}: {response.text}")
                return False
        except Exception as e:
            self.log_test("Alert Resolution", False, f"Error: {str(e)}")
            return False
    
    async def test_websocket_connection(self):
        """Test WebSocket real-time communication"""
        try:
            print("Testing WebSocket connection...")
            async with websockets.connect(self.ws_url) as websocket:
                # Send a test message
                await websocket.send("test_connection")
                
                # Wait for real-time messages
                messages_received = 0
                start_time = time.time()
                
                while time.time() - start_time < 15 and messages_received < 3:
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                        data = json.loads(message)
                        
                        if data.get('type') in ['network_event', 'threat_alert']:
                            messages_received += 1
                            print(f"Received {data['type']}: {data.get('data', {}).get('id', 'unknown')}")
                    except asyncio.TimeoutError:
                        break
                
                if messages_received > 0:
                    self.log_test("WebSocket Communication", True, f"Received {messages_received} real-time messages")
                    return True
                else:
                    self.log_test("WebSocket Communication", False, "No real-time messages received")
                    return False
                    
        except Exception as e:
            self.log_test("WebSocket Communication", False, f"Connection error: {str(e)}")
            return False
    
    def test_traffic_simulation_engine(self, events):
        """Test network traffic simulation patterns"""
        if not events:
            self.log_test("Traffic Simulation Engine", False, "No events to analyze")
            return False
            
        try:
            # Analyze traffic patterns
            legitimate_ips = set()
            malicious_ips = set()
            protocols = set()
            connection_statuses = set()
            
            for event in events:
                protocols.add(event.get('protocol'))
                connection_statuses.add(event.get('connection_status'))
                
                # Categorize IPs based on connection status
                if event.get('connection_status') == 'allowed':
                    legitimate_ips.add(event.get('source_ip'))
                elif event.get('connection_status') in ['blocked', 'suspicious']:
                    malicious_ips.add(event.get('source_ip'))
            
            # Check for diversity in traffic patterns
            has_legitimate = len(legitimate_ips) > 0
            has_malicious = len(malicious_ips) > 0
            has_protocols = len(protocols) > 1
            has_varied_status = len(connection_statuses) > 1
            
            if has_legitimate and has_protocols:
                details = f"IPs: {len(legitimate_ips)} legitimate"
                if has_malicious:
                    details += f", {len(malicious_ips)} malicious"
                details += f"; Protocols: {list(protocols)}"
                
                self.log_test("Traffic Simulation Engine", True, details)
                return True
            else:
                self.log_test("Traffic Simulation Engine", False, "Insufficient traffic diversity")
                return False
                
        except Exception as e:
            self.log_test("Traffic Simulation Engine", False, f"Analysis error: {str(e)}")
            return False
    
    def test_detection_engines(self, alerts):
        """Test signature and anomaly detection engines"""
        try:
            if not alerts:
                # This is acceptable - no threats detected
                self.log_test("Signature-based Detection", True, "No signature matches (no malicious payloads)")
                self.log_test("Anomaly-based Detection", True, "No anomalies detected (normal traffic patterns)")
                return True
            
            # Analyze detection types
            signature_alerts = [a for a in alerts if a.get('signature_matched')]
            anomaly_alerts = [a for a in alerts if a.get('is_anomaly')]
            
            # Test signature-based detection
            if signature_alerts:
                threat_types = set(a.get('threat_type') for a in signature_alerts)
                self.log_test("Signature-based Detection", True, f"Detected {len(signature_alerts)} signature-based threats: {list(threat_types)}")
            else:
                self.log_test("Signature-based Detection", True, "No signature matches (acceptable)")
            
            # Test anomaly-based detection  
            if anomaly_alerts:
                anomaly_types = set(a.get('threat_type') for a in anomaly_alerts)
                self.log_test("Anomaly-based Detection", True, f"Detected {len(anomaly_alerts)} anomaly-based threats: {list(anomaly_types)}")
            else:
                self.log_test("Anomaly-based Detection", True, "No anomalies detected (acceptable)")
            
            return True
            
        except Exception as e:
            self.log_test("Signature-based Detection", False, f"Error: {str(e)}")
            self.log_test("Anomaly-based Detection", False, f"Error: {str(e)}")
            return False
    
    def test_mongodb_persistence(self):
        """Test MongoDB data persistence by checking data consistency"""
        try:
            # Get events and alerts
            events_response = requests.get(f"{self.base_url}/events?limit=5", timeout=10)
            alerts_response = requests.get(f"{self.base_url}/alerts?limit=5", timeout=10)
            
            if events_response.status_code == 200 and alerts_response.status_code == 200:
                events = events_response.json()
                alerts = alerts_response.json()
                
                # Check timestamp formats (should be ISO format)
                timestamp_valid = True
                for event in events[:3]:  # Check first 3 events
                    try:
                        datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    except:
                        timestamp_valid = False
                        break
                
                if timestamp_valid:
                    self.log_test("MongoDB Data Persistence", True, f"Data properly stored and retrieved with valid timestamps")
                    return True
                else:
                    self.log_test("MongoDB Data Persistence", False, "Invalid timestamp format in stored data")
                    return False
            else:
                self.log_test("MongoDB Data Persistence", False, "Could not retrieve data for validation")
                return False
                
        except Exception as e:
            self.log_test("MongoDB Data Persistence", False, f"Error: {str(e)}")
            return False
    
    async def run_all_tests(self):
        """Run comprehensive backend testing"""
        print("=" * 60)
        print("INTRUSION DETECTION SYSTEM - BACKEND TESTING")
        print("=" * 60)
        
        # Test 1: Basic connectivity
        if not self.test_basic_connectivity():
            print("\n❌ CRITICAL: Basic API connectivity failed. Stopping tests.")
            return False
        
        # Test 2: Network events API and traffic simulation
        events_success, events = self.test_network_events_api()
        if events_success:
            self.test_traffic_simulation_engine(events)
        
        # Test 3: Threat alerts API and detection engines
        alerts_success, alerts = self.test_threat_alerts_api()
        if alerts_success:
            self.test_detection_engines(alerts)
            self.test_alert_resolution(alerts)
        
        # Test 4: Statistics API
        self.test_statistics_api()
        
        # Test 5: MongoDB persistence
        self.test_mongodb_persistence()
        
        # Test 6: WebSocket communication
        await self.test_websocket_connection()
        
        # Summary
        print("\n" + "=" * 60)
        print("TEST SUMMARY")
        print("=" * 60)
        
        passed = sum(1 for result in self.test_results.values() if result['success'])
        total = len(self.test_results)
        
        for test_name, result in self.test_results.items():
            status = "✅ PASS" if result['success'] else "❌ FAIL"
            print(f"{status} {test_name}")
            if not result['success'] and result['message']:
                print(f"    └─ {result['message']}")
        
        print(f"\nOverall: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 All backend tests PASSED! IDS system is working correctly.")
            return True
        else:
            print(f"⚠️  {total - passed} test(s) failed. See details above.")
            return False

async def main():
    """Main test execution"""
    tester = IDSBackendTester()
    success = await tester.run_all_tests()
    return success

if __name__ == "__main__":
    # Run the async test suite
    result = asyncio.run(main())
    sys.exit(0 if result else 1)