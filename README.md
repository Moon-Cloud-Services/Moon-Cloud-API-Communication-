## Moon Cloud Services - VM Communication API & Discord Bot

**Overview**

Moon Cloud Services provides a secure API and Discord bot for communication and management of virtual machines (VMs). This system enables remote control of VMs directly via Discord commands and offers real-time updates through WebSockets.

**Features**

* **JWT authentication** for the API and **Fernet encryption** for secure communication
* **RESTful API** for virtual machine control (start, stop, reboot, etc.)
* **Real-time updates** via WebSocket
* **Full integration with Discord** to manage VMs via commands

**Quick Start**

**Prerequisites**

* Python 3.8+
* pip (Python package manager)
* PostgreSQL (or SQLite for development)
* Discord Developer Account

**Installation**

1. Clone the repository:

```bash
git clone https://github.com/Moon-Cloud-Services/Moon-Cloud-API-Communication-.git
cd moon-cloud-services
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Configure environment variables for the API and bot:

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

4. Set up and run the API server:

   * Run database migrations:

     ```bash
     alembic upgrade head
     ```

   * Start the API server:

     ```bash
     uvicorn main:app --reload
     ```

5. Set up and run the Discord bot:

   * Define the bot token and run the bot:

     ```bash
     python discord_bot.py
     ```

**Usage**

## Discord Bot Commands

* `!startvm [server_id]`: Start a virtual machine
* `!stopvm [server_id]`: Stop a virtual machine
* `!rebootvm [server_id]`: Reboot a virtual machine
* `!statusvm [server_id]`: Get the status of a virtual machine
* `!listservers`: List all available servers
* `!backupserver <server_id>`: Initiate a backup for a specific server
* `!serverresources <server_id>`: Get resource usage for a server
* `!serverlogs <server_id>`: Get server logs
* `!scheduletask <server_id> <task>`: Schedule a task for a server

## API Endpoints

* `POST /token`: Obtain access token
* `POST /execute_command`: Execute a VM command (start, stop, reboot)
* `GET /servers`: List all available servers
* `POST /servers/{server_id}/backup`: Backup a specific server
* `GET /servers/{server_id}/resources`: Get server resource usage
* `GET /servers/{server_id}/logs`: Get logs for a specific server

## WebSocket Real-Time Updates

The API supports real-time updates through WebSockets, allowing you to monitor VM statuses and receive notifications directly.

**Example WebSocket connection:**

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

**Documentation**

For detailed API documentation and advanced usage, please refer to the full documentation.

**Security**

* The API uses JWT authentication to secure requests.
* Communication between the API and servers is protected using Fernet encryption.
* Ensure that all keys are kept secure and use HTTPS in production environments.
* Messages sent via WebSocket are also encrypted using Fer
