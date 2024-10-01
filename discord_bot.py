import os
import discord
from discord.ext import commands
import aiohttp
import asyncio
import websockets
import json
from Crypto.Cipher import AES
import base64

# Bot configuration
TOKEN = os.getenv('DISCORD_TOKEN')
API_URL = os.getenv('API_URL')
WS_URL = os.getenv('WS_URL')
WS_API_KEY = os.getenv('WS_API_KEY')

# AES encryption key
AES_KEY = base64.b64decode(os.getenv('AES_KEY'))

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Encryption functions
def encrypt_message(message: str) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(encrypted_message: str) -> str:
    encrypted = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    bot.loop.create_task(websocket_handler())

async def websocket_handler():
    while True:
        try:
            async with websockets.connect(
                WS_URL,
                extra_headers={'X-API-Key': WS_API_KEY}
            ) as websocket:
                while True:
                    message = await websocket.recv()
                    decrypted_message = decrypt_message(message)
                    print(f"Received from WebSocket: {decrypted_message}")
                    # Here you can add logic to process the received message
        except Exception as e:
            print(f"WebSocket error: {str(e)}")
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
            await ctx.send(f"Error communicating with the API: {str(e)}")

@bot.command()
async def startvm(ctx, server_id: str = None):
    await execute_command(ctx, "start", server_id)

@bot.command()
async def stopvm(ctx, server_id: str = None):
    await execute_command(ctx, "stop", server_id)

@bot.command()
async def rebootvm(ctx, server_id: str = None):
    await execute_command(ctx, "reboot", server_id)

@bot.command()
async def statusvm(ctx, server_id: str = None):
    await execute_command(ctx, "status", server_id)

@bot.command()
async def listservers(ctx):
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
            await ctx.send(f"Error communicating with the API: {str(e)}")

@bot.command()
async def backupserver(ctx, server_id: str):
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
            await ctx.send(f"Error communicating with the API: {str(e)}")

@bot.command()
async def serverresources(ctx, server_id: str):
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
            await ctx.send(f"Error communicating with the API: {str(e)}")

@bot.command()
async def serverlogs(ctx, server_id: str):
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
            await ctx.send(f"Error communicating with the API: {str(e)}")

@bot.command()
async def scheduletask(ctx, server_id: str, *, task: str):
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
            await ctx.send(f"Error communicating with the API: {str(e)}")

@bot.command()
async def help(ctx, command: str = None):
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
        command_help = {
            "startvm": "Start a virtual machine. Usage: !startvm [server_id]",
            "stopvm": "Stop a virtual machine. Usage: !stopvm [server_id]",
            "rebootvm": "Reboot a virtual machine. Usage: !rebootvm [server_id]",
            "statusvm": "Get the status of a virtual machine. Usage: !statusvm [server_id]",
            "listservers": "List all available servers. Usage: !listservers",
            "backupserver": "Initiate a backup for a specific server. Usage: !backupserver <server_id>",
            "serverresources": "Get resource usage for a specific server. Usage: !serverresources <server_id>",
            "serverlogs": "Get logs for a specific server. Usage: !serverlogs <server_id>",
            "scheduletask": "Schedule a task for a specific server. Usage: !scheduletask <server_id> <task>"
        }
        await ctx.send(command_help.get(command, f"Unknown command: {command}"))

# Bot execution
bot.run(TOKEN)
