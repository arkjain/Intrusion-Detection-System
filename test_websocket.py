#!/usr/bin/env python3
import asyncio
import websockets
import json

async def test_websocket():
    try:
        uri = "wss://intrusion-shield.preview.emergentagent.com/ws"
        print(f"Connecting to {uri}...")
        
        async with websockets.connect(uri) as websocket:
            print("✅ WebSocket connected successfully!")
            
            # Send a test message
            await websocket.send("test")
            print("📤 Sent test message")
            
            # Wait for messages for 10 seconds
            try:
                for i in range(10):
                    message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    try:
                        data = json.loads(message)
                        print(f"📥 Received: {data.get('type', 'unknown')} - {data.get('data', {}).get('id', 'no-id')}")
                    except json.JSONDecodeError:
                        print(f"📥 Received raw: {message[:100]}...")
                    
            except asyncio.TimeoutError:
                print("⏰ No more messages received")
                
    except Exception as e:
        print(f"❌ WebSocket error: {e}")

if __name__ == "__main__":
    asyncio.run(test_websocket())