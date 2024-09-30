# discord_bot.py
import discord
from discord.ext import commands
import aiohttp
import asyncio
import websockets
import json
from Crypto.Cipher import AES
import base64

# Bot configuration
TOKEN = 'your_discord_token'
API_URL = 'http://localhost:8000'
WS_URL = 'ws://localhost:8000/ws'

# AES encryption key (must be the same as in the API)
AES_KEY = b'32_byte_aes_key_here____________'  # 32 bytes = 256 bits

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

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
            async with websockets.connect(WS_URL) as websocket:
                while True:
                    message = await websocket.recv()
                    decrypted_message = decrypt_message(message)
                    print(f"Received from WebSocket: {decrypted_message}")
                    # Here you can add logic to process the received message
        except Exception as e:
            print(f"WebSocket error: {str(e)}")
            await asyncio.sleep(5)  # Wait before trying to reconnect

@bot.command()
async def startvm(ctx):
    async with aiohttp.ClientSession() as session:
        async with session.post(f'{API_URL}/execute_command', 
                                json={"action": "start_vm"},
                                headers={"Authorization": f"Bearer {TOKEN}"}) as response:
            if response.status == 200:
                data = await response.json()
                decrypted_response = decrypt_message(data['response'])
                await ctx.send(f"VM started: {decrypted_response}")
            else:
                await ctx.send("Failed to start VM")

@bot.command()
async def statusvm(ctx):
    async with aiohttp.ClientSession() as session:
        async with session.post(f'{API_URL}/execute_command', 
                                json={"action": "status_vm"},
                                headers={"Authorization": f"Bearer {TOKEN}"}) as response:
            if response.status == 200:
                data = await response.json()
                decrypted_response = decrypt_message(data['response'])
                await ctx.send(f"VM status: {decrypted_response}")
            else:
                await ctx.send("Failed to get VM status")

bot.run(TOKEN)
