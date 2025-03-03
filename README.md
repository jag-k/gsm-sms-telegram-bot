# GSM SMS Telegram Bot

[![Python](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
![GitHub License](https://img.shields.io/github/license/jag-k/gsm-sms-telegram-bot)

*Send and receive SMS via Telegram using a GSM modem*

This bot allows you to send and receive SMS messages through Telegram using a GSM modem connected to your device.

## Features

- Receive SMS messages in Telegram
- Send SMS messages via Telegram
- Reply directly to incoming messages
- View message history
- Merge multi-part messages
- International phone number formatting

## Requirements

- Python 3.13 or higher
- GSM modem (connected via USB)
- Telegram Bot Token

## Installation

### Using Docker (recommended)

Requirements:

- GSM modem (connected via USB)
- Telegram Bot Token
- Docker
- Docker Compose (optional)
- curl (optional) — only for downloading `compose.yml` and `.env.example` files, otherwise you can download them manually

```bash
# Copy compose file and .env.example
curl -o compose.yml https://raw.githubusercontent.com/jag-k/gsm-sms-telegram-bot/main/compose.yml
curl -o .env https://raw.githubusercontent.com/jag-k/gsm-sms-telegram-bot/main/.env.example

# Configure your settings
cp .env.example .env
# Edit .env with your settings
nano .env

# Start the container
docker compose up -d
```

### Manual Installation

Requirements:

- Python 3.13 or higher
- GSM modem (connected via USB)
- Telegram Bot Token
- [uv](https://github.com/astral-sh/uv)

```bash
# Clone the repository
git clone https://github.com/jag-k/gsm-sms-telegram-bot.git
cd gsm-sms-telegram-bot

# Install dependencies using uv
uv sync

# Configure your settings
cp .env.example .env
# Edit .env with your settings
nano .env

# Run the bot
python src/main.py
```

## Configuration

Configure the bot by editing the `.env` file:

```
# Required settings
BOT__TOKEN=your_telegram_bot_token
BOT__ALLOWED_USER_ID=your_telegram_user_id

# Optional settings (defaults shown)
# MODEM__MODEM_PORT="/dev/ttyUSB0"
# MODEM__BAUD_RATE=115200
# MODEM__DEFAULT_REGION="US"
```

See [Configuration.md](Configuration.md) for detailed settings documentation.

## Usage

1. Start the bot with `python src/main.py` or via Docker
2. Open your Telegram app and message your bot
3. Use the following commands:
   - `/start` - Show recent SMS messages
   - `/send` - Send an SMS message

### Sending SMS Messages

There are several ways to send SMS:
- `/send phone_number message` - Send directly with one command
- `/send phone_number` - Bot will ask for the message text
- `/send` - Bot will ask for phone number and message
- Forward a contact to the bot - Bot will ask for message text
- Reply to an SMS message — Automatically send your reply to that number

## License

[MIT]
