import os
import discord
from discord.ext import commands
import aiohttp
import asyncio
import websockets
import json
from cryptography.fernet import Fernet
import logging
from datetime import datetime

# Bot configuration
TOKEN = os.getenv('DISCORD_BOT_TOKEN')
API_URL = os.getenv('API_URL')
WS_URL = os.getenv('WS_URL')
WS_API_KEY = os.getenv('WS_API_KEY')

# Fernet encryption key
FERNET_KEY = os.getenv('FERNET_KEY').encode()
fernet = Fernet(FERNET_KEY)

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Encryption functions
def encrypt_message(message: str) -> str:
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message: str) -> str:
    return fernet.decrypt(encrypted_message.encode()).decode()

@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    bot.loop.create_task(websocket_handler())

async def websocket_handler():
    while True:
        try:
            async with websockets.connect(
                WS_URL,
                extra_headers={'X-API-Key': WS_API_KEY}
            ) as websocket:
                logger.info("Connected to WebSocket")
                while True:
                    message = await websocket.recv()
                    decrypted_message = decrypt_message(message)
                    logger.info(f"Received from WebSocket: {decrypted_message}")
                    # Here you can add logic to process the received message
                    # For example, send it to a specific Discord channel
                    channel = bot.get_channel(int(os.getenv('NOTIFICATION_CHANNEL_ID')))
                    if channel:
                        await channel.send(f"Server update: {decrypted_message}")
        except Exception as e:
            logger.error(f"WebSocket error: {str(e)}")
            await asyncio.sleep(5)  # Wait before trying to reconnect

async def execute_command(ctx, action, server_id=None):
    async with aiohttp.ClientSession() as session:
        try:
            url = f'{API_URL}/execute_command'
            if server_id:
                url += f'/{server_id}'
            async with session.post(
                url, 
                json={"action": action},
                headers={"Authorization": f"Bearer {TOKEN}"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    decrypted_response = decrypt_message(data['response'])
                    await ctx.send(f"Command result: {decrypted_response}")
                else:
                    await ctx.send(f"Failed to execute command. Status: {response.status}")
        except aiohttp.ClientError as e:
            logger.error(f"Error communicating with the API: {str(e)}")
            await ctx.send(f"Error communicating with the API. Please try again later.")

@bot.command(name="startvm")
async def startvm(ctx, server_id: str = None):
    """Start a virtual machine"""
    await execute_command(ctx, "start", server_id)

@bot.command(name="stopvm")
async def stopvm(ctx, server_id: str = None):
    """Stop a virtual machine"""
    await execute_command(ctx, "stop", server_id)

@bot.command(name="rebootvm")
async def rebootvm(ctx, server_id: str = None):
    """Reboot a virtual machine"""
    await execute_command(ctx, "reboot", server_id)

@bot.command(name="statusvm")
async def statusvm(ctx, server_id: str = None):
    """Get the status of a virtual machine"""
    await execute_command(ctx, "status", server_id)

@bot.command(name="listservers")
async def listservers(ctx):
    """List all available servers"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(
                f'{API_URL}/servers',
                headers={"Authorization": f"Bearer {TOKEN}"}
            ) as response:
                if response.status == 200:
                    servers = await response.json()
                    server_list = "\n".join([f"ID: {s['id']}, Name: {s['name']}, Status: {s['status']}" for s in servers])
                    await ctx.send(f"Available servers:\n{server_list}")
                else:
                    await ctx.send(f"Failed to retrieve server list. Status: {response.status}")
        except aiohttp.ClientError as e:
            logger.error(f"Error communicating with the API: {str(e)}")
            await ctx.send(f"Error communicating with the API. Please try again later.")

@bot.command(name="backupserver")
async def backupserver(ctx, server_id: str):
    """Initiate a backup for a specific server"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f'{API_URL}/servers/{server_id}/backup',
                headers={"Authorization": f"Bearer {TOKEN}"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    await ctx.send(f"Backup initiated: {data['message']}")
                else:
                    await ctx.send(f"Failed to initiate backup. Status: {response.status}")
        except aiohttp.ClientError as e:
            logger.error(f"Error communicating with the API: {str(e)}")
            await ctx.send(f"Error communicating with the API. Please try again later.")

@bot.command(name="serverresources")
async def serverresources(ctx, server_id: str):
    """Get resource usage for a specific server"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(
                f'{API_URL}/servers/{server_id}/resources',
                headers={"Authorization": f"Bearer {TOKEN}"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    await ctx.send(f"Server resources:\nCPU: {data['cpu']}\nMemory: {data['memory']}\nDisk: {data['disk']}")
                else:
                    await ctx.send(f"Failed to retrieve server resources. Status: {response.status}")
        except aiohttp.ClientError as e:
            logger.error(f"Error communicating with the API: {str(e)}")
            await ctx.send(f"Error communicating with the API. Please try again later.")

@bot.command(name="serverlogs")
async def serverlogs(ctx, server_id: str):
    """Get logs for a specific server"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(
                f'{API_URL}/servers/{server_id}/logs',
                headers={"Authorization": f"Bearer {TOKEN}"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    await ctx.send(f"Server logs:\n{data['logs']}")
                else:
                    await ctx.send(f"Failed to retrieve server logs. Status: {response.status}")
        except aiohttp.ClientError as e:
            logger.error(f"Error communicating with the API: {str(e)}")
            await ctx.send(f"Error communicating with the API. Please try again later.")

@bot.command(name="scheduletask")
async def scheduletask(ctx, server_id: str, *, task: str):
    """Schedule a task for a specific server"""
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f'{API_URL}/servers/{server_id}/schedule',
                json={"task": task},
                headers={"Authorization": f"Bearer {TOKEN}"}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    await ctx.send(f"Task scheduled: {data['message']}")
                else:
                    await ctx.send(f"Failed to schedule task. Status: {response.status}")
        except aiohttp.ClientError as e:
            logger.error(f"Error communicating with the API: {str(e)}")
            await ctx.send(f"Error communicating with the API. Please try again later.")

@bot.command(name="help")
async def help_command(ctx, command: str = None):
    """Show help information for commands"""
    if command is None:
        help_text = """
Available commands:
- !startvm [server_id]: Start a virtual machine
- !stopvm [server_id]: Stop a virtual machine
- !rebootvm [server_id]: Reboot a virtual machine
- !statusvm [server_id]: Get the status of a virtual machine
- !listservers: List all available servers
- !backupserver <server_id>: Initiate a backup for a specific server
- !serverresources <server_id>: Get resource usage for a specific server
- !serverlogs <server_id>: Get logs for a specific server
- !scheduletask <server_id> <task>: Schedule a task for a specific server

Use !help <command> for more information on a specific command.
"""
        await ctx.send(help_text)
    else:
        command_obj = bot.get_command(command)
        if command_obj:
            await ctx.send(f"{command}: {command_obj.help}")
        else:
            await ctx.send(f"Unknown command: {command}")

# Error handling
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("Unknown command. Use !help to see available commands.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"Missing required argument: {error.param}")
    else:
        logger.error(f"Unhandled error: {str(error)}")
        await ctx.send("An error occurred while processing your command. Please try again later.")

# Bot execution
if __name__ == "__main__":
    bot.run(TOKEN)
