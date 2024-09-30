# Discord Bot - VM Communication API

## Overview
This project provides a secure API for communication between a Discord bot and virtual machines. It enables remote control and monitoring of VMs through Discord commands.

## Features
- Secure communication using JWT authentication and AES-256 encryption
- RESTful API for VM control (reboot, shutdown, etc.)
- Real-time status updates via WebSocket
- Integration with Discord bots

## Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation
1. Clone the repository:
   ```
   git clone https://github.com/Moon-Cloud-Services/Moon-Cloud-API-Communication-.git
   cd discord-vm-api
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure the API:
   - Set your JWT secret key in `api.py`
   - Generate and set your AES key in both `api.py` and `discord_bot.py`

4. Run the API:
   ```
   python api.py
   ```

5. Configure and run the Discord bot:
   - Set your Discord bot token in `discord_bot.py`
   - Run the bot:
     ```
     python discord_bot.py
     ```

## Usage
- Use Discord commands to control VMs: `!startvm`, `!statusvm`, etc.
- Send API requests to `http://localhost:8000/execute_command` with proper JWT authentication

## Documentation
For detailed API documentation and advanced usage, please refer to the [full documentation](https://github.com/Moon-Cloud-Services/Moon-Cloud-API-Communication-/blob/main/DOCUMENTATION.md). 

## Security
This API uses JWT for authentication and AES-256 for encryption. Ensure to keep all keys secure and use HTTPS in production.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support
For support, please open an issue in the GitHub issue tracker or contact the development team at https://discord.gg/SZ5AVdYa6e
