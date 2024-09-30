# Discord Bot - Virtual Machine Communication System Documentation

## Introduction

This system consists of a custom communication API that enables interaction between a Discord bot and virtual machines hosted on servers. The system is designed in a modular and flexible manner, allowing for easy adaptation to other communication purposes in the future.

## Installation and Configuration

### Requirements

- Python 3.8+
- pip (Python package manager)

### Installation

1. Clone the repository or download the `api.py` and `discord_bot.py` files.

2. Install the necessary dependencies:

```bash
pip install fastapi uvicorn pyjwt pycryptodome discord.py aiohttp websockets
```

### Configuration

1. API (api.py):
   - Set a secret key for JWT: Replace `"your-secret-key"` with a secure key.
   - Generate an AES-256 key: Replace `get_random_bytes(32)` with a securely generated AES-256 key.

2. Discord Bot (discord_bot.py):
   - Insert your Discord bot token.
   - Configure the API URL.
   - Set the AES key (must be the same as used in the API).

## JWT Authentication

The system uses JWT (JSON Web Token) authentication to protect API requests.

### Obtaining a Token

To obtain a JWT token, make a POST request to the `/token` endpoint:

```python
import requests

response = requests.post(
    "http://localhost:8000/token",
    data={"username": "testuser", "password": "testpassword"}
)
token = response.json()["access_token"]
```

### Using the Token

Include the token in the `Authorization` header of all subsequent requests:

```python
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    "http://localhost:8000/execute_command",
    json={"action": "reboot"},
    headers=headers
)
```

## Supported Commands

The API supports the following commands:

1. Reboot
2. Shutdown
3. Status (via WebSocket)

### Usage Examples

```python
# Reboot
response = requests.post(
    "http://localhost:8000/execute_command",
    json={"action": "reboot"},
    headers=headers
)

# Shutdown
response = requests.post(
    "http://localhost:8000/execute_command",
    json={"action": "shutdown"},
    headers=headers
)
```

## Real-Time Communication (WebSocket)

The system supports real-time communication via WebSocket for status monitoring and direct communication with virtual machines.

### Connecting to WebSocket

```python
import websockets
import asyncio
import json

async def connect_websocket():
    uri = "ws://localhost:8000/ws"
    async with websockets.connect(uri) as websocket:
        while True:
            message = json.dumps({"action": "status"})
            await websocket.send(encrypt_message(message))
            response = await websocket.recv()
            print(decrypt_message(response))

asyncio.get_event_loop().run_until_complete(connect_websocket())
```

## Security

### AES-256 Encryption

All communication between the API and servers is protected using AES-256 encryption. The `encrypt_message()` and `decrypt_message()` functions are used to encrypt and decrypt messages, respectively.

### Protection of Sensitive Data

- JWT tokens are used for authentication, with limited expiration time.
- Secret keys (JWT and AES) are stored securely and not exposed publicly.
- All communications via API and WebSocket are encrypted.

## Final Considerations

- In a production environment, use HTTPS for the API and WSS for WebSockets.
- Implement additional security practices, such as rate limiting and rigorous input validation.
- Keep secret keys and tokens secure and do not share them publicly.

For additional support or questions, contact the development team.
