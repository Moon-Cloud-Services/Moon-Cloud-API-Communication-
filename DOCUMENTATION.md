# Moon Cloud Services - Virtual Machine Management System Documentation

## Introduction

Moon Cloud Services is an open-source project that provides a comprehensive virtual machine management solution. It consists of a FastAPI-based API for server management and a Discord bot for easy interaction. The system is designed to be modular and flexible, allowing for future expansion and adaptation to various cloud management needs.

## Components

1. FastAPI Application (API)
2. Discord Bot
3. WebSocket Server for real-time updates

## Installation and Configuration

### Requirements

- Python 3.8+
- PostgreSQL (or SQLite for development)
- pip (Python package manager)
- Discord Developer Account

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Moon-Cloud-Services/Moon-Cloud-API-Communication-.git
   cd moon-cloud-services
   ```

2. Install the necessary dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Configuration

Set up the following environment variables:

```
DATABASE_URL=postgresql://user:password@localhost/dbname
JWT_SECRET_KEY=your_secret_key
FERNET_KEY=your_fernet_key
DISCORD_BOT_TOKEN=your_discord_bot_token
API_URL=http://localhost:8000
WS_URL=ws://localhost:8000/ws
WS_API_KEY=your_websocket_api_key
NOTIFICATION_CHANNEL_ID=your_discord_channel_id
```

### API Setup

1. Run database migrations:
   ```bash
   alembic upgrade head
   ```

2. Start the API server:
   ```bash
   uvicorn main:app --reload
   ```

### Discord Bot Setup

1. Create a new Discord application and bot in the Discord Developer Portal.
2. Add the bot to your Discord server.
3. Run the Discord bot:
   ```bash
   python discord_bot.py
   ```

## Authentication

The system uses JWT (JSON Web Token) authentication to secure API requests.

### Obtaining a Token

To obtain a JWT token, make a POST request to the `/token` endpoint:

```python
import requests

response = requests.post(
    "http://localhost:8000/token",
    data={"username": "your_username", "password": "your_password"}
)
token = response.json()["access_token"]
```

### Using the Token

Include the token in the `Authorization` header of all subsequent requests:

```python
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    "http://localhost:8000/execute_command",
    json={"action": "start"},
    headers=headers
)
```

## API Endpoints

- POST `/token`: Obtain access token
- POST `/users`: Create a new user
- POST `/execute_command`: Execute a VM command
- GET `/servers`: List all servers
- POST `/servers/{server_id}/backup`: Initiate a server backup
- GET `/servers/{server_id}/resources`: Get server resources
- GET `/servers/{server_id}/logs`: Get server logs
- POST `/servers/{server_id}/schedule`: Schedule a task for a server
- WebSocket `/ws`: Real-time server updates

## Supported Commands

The API supports the following commands:

1. Start
2. Stop
3. Reboot
4. Status

### Usage Examples

```python
# Start a VM
response = requests.post(
    "http://localhost:8000/execute_command",
    json={"action": "start"},
    headers=headers
)

# Stop a VM
response = requests.post(
    "http://localhost:8000/execute_command",
    json={"action": "stop"},
    headers=headers
)
```

## Discord Bot Commands

- `!startvm [server_id]`: Start a virtual machine
- `!stopvm [server_id]`: Stop a virtual machine
- `!rebootvm [server_id]`: Reboot a virtual machine
- `!statusvm [server_id]`: Get the status of a virtual machine
- `!listservers`: List all available servers
- `!backupserver <server_id>`: Initiate a backup for a specific server
- `!serverresources <server_id>`: Get resource usage for a specific server
- `!serverlogs <server_id>`: Get logs for a specific server
- `!scheduletask <server_id> <task>`: Schedule a task for a specific server
- `!help [command]`: Show help information for commands

## Real-Time Communication (WebSocket)

The system supports real-time communication via WebSocket for status monitoring and direct communication with virtual machines.

### Connecting to WebSocket

```python
import websockets
import asyncio
import json
from cryptography.fernet import Fernet

fernet = Fernet(FERNET_KEY)

async def connect_websocket():
    uri = "ws://localhost:8000/ws"
    async with websockets.connect(uri, extra_headers={'X-API-Key': WS_API_KEY}) as websocket:
        while True:
            message = json.dumps({"action": "status"})
            encrypted_message = fernet.encrypt(message.encode()).decode()
            await websocket.send(encrypted_message)
            response = await websocket.recv()
            decrypted_response = fernet.decrypt(response.encode()).decode()
            print(decrypted_response)

asyncio.get_event_loop().run_until_complete(connect_websocket())
```

## Security

### Fernet Encryption

All communication between the API and servers is protected using Fernet encryption. The `encrypt_message()` and `decrypt_message()` functions are used to encrypt and decrypt messages, respectively.

### Protection of Sensitive Data

- JWT tokens are used for authentication, with limited expiration time.
- Secret keys (JWT and Fernet) are stored securely as environment variables.
- All communications via API and WebSocket are encrypted.
- Passwords are hashed using bcrypt before storage.

## Error Handling and Logging

Both the API and Discord bot implement comprehensive error handling and logging. Logs are stored in the application's log files and should be regularly monitored for any issues or security concerns.

## Scalability

To scale the application:
- Use a production-grade database like PostgreSQL
- Implement caching (e.g., Redis) for frequently accessed data
- Use a load balancer for distributing API requests
- Consider containerization (Docker) and orchestration (Kubernetes) for easier deployment and scaling

## Final Considerations

- In a production environment, use HTTPS for the API and WSS for WebSockets.
- Implement additional security practices, such as rate limiting and rigorous input validation.
- Regularly rotate JWT secret keys and Fernet keys.
- Keep all dependencies up to date.
- Monitor system logs and performance metrics.

For additional support or questions, please open an issue in the GitHub repository or contact the Moon Cloud Services development team.
