#!/usr/bin/env python3
import asyncio
import websockets
import json

async def test_websocket():
    try:
        # Try backend WebSocket directly
        uri = "wss://intrusion-shield.preview.emergentagent.com/ws"
        print(f"Connecting to {uri}...")
        
        async with websockets.connect(uri) as websocket:
            print("✅ WebSocket connected successfully!")
            
            # Send a test message
            await websocket.send("test")
            print("📤 Sent test message")
            
            # Wait for messages for 15 seconds
            messages_received = 0
            try:
                for i in range(15):
                    message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    try:
                        data = json.loads(message)
                        if isinstance(data, dict) and data.get('type') in ['network_event', 'threat_alert']:
                            print(f"📥 IDS Message: {data.get('type')} - {data.get('data', {}).get('id', 'no-id')}")
                            messages_received += 1
                        else:
                            print(f"📥 Other message: {str(data)[:100]}...")
                    except (json.JSONDecodeError, AttributeError):
                        print(f"📥 Raw message: {str(message)[:100]}...")
                    
            except asyncio.TimeoutError:
                print("⏰ Timeout waiting for messages")
                
            print(f"Total IDS messages received: {messages_received}")
            return messages_received > 0
                
    except Exception as e:
        print(f"❌ WebSocket error: {e}")
        return False

if __name__ == "__main__":
    asyncio.run(test_websocket())