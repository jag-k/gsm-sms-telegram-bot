# GSM SMS Telegram Bot Development Guide

## Development Commands

- Install dependencies: `uv sync`
- Lint and format code: `uv run ruff check src/ --fix && ruff format src/`
- Type check: `uv run ty check src/`
- Run checks (all): `uv run pre-commit run --all-files`

> **Note:** The bot cannot be run locally — it requires a physical GSM modem connected to a Raspberry Pi.
> Changes can only be tested on the Raspberry Pi after the container image is built and deployed there.
> Do NOT push to GitHub or trigger any deployment — that is the developer's responsibility.

## Code Style Guidelines

- Python version: 3.13+
- Line length: 120 characters
- Use absolute imports (`ban-relative-imports = "parents"`)
- Follow PEP8 naming conventions
- Error handling: Catch specific exceptions, log with context
- Type annotations: Required for all function definitions
- Docstrings: Use rst-style for documentation
- Format imports with sections: stdlib → third-party → first-party
- Max function complexity: 6 (McCabe)

## Performance Preferences

- Prefer simplicity to complex optimization patterns
- Minimize unnecessary waiting times in modem communication:
    - Use fixed, minimal timeouts instead of adaptive polling when possible
    - Default delay for AT commands: 0.1s (only when required)
    - Use simple, linear approaches for serial device communication
- GSM modem is a serial device - process one command at a time
- Straight-line code is preferred over complex control flow
- Aim for readability and maintainability over clever optimizations

## Complexity Management

- Break complex methods into smaller, focused helper methods
- Prioritize low complexity over performance hacks
- If a method exceeds complexity limits, refactor rather than increasing thresholds
- Simplify waiting/polling logic when working with serial devices
- Don't overengineer adaptive strategies for simple serial communication

## Project Structure

- `src/`: Main package
    - `main.py`: Entry point — starts the bot
    - `config.py`: Configuration via Pydantic settings
    - `bot/`: Telegram bot layer
        - `main.py`: `SMSBot` class — thin orchestrator, lifecycle, SMS sending
        - `threads.py`: `ThreadManager` — forum topic management, phone↔thread mapping
        - `storage.py`: `SMSStorage` — SMS persistence in bot_data
        - `utils.py`: Helpers (`retry_telegram_api`, phone formatting, access checks, error handler)
        - `handlers/`: Telegram update handlers
            - `__init__.py`: `register_handlers()` — wires all handlers to the application
            - `commands.py`: `/start`, `/clear`, `/rebuild` commands, `set_bot_commands`
            - `send.py`: `/send` conversation flow, contact handling
            - `messages.py`: Thread message and SMS reply handlers
    - `sms_reader/`: GSM modem and SMS handling
        - `facade.py`: `GSMModem` — public facade that composes all modem components
        - `modem.py`: `ModemController` — AT command execution
        - `transport.py`: `ModemTransport` — serial connection and `ModemConnectionLostError`
        - `monitor.py`: `SMSMonitor` — polls modem for incoming SMS
        - `message_queue.py`: `MessageQueue` — async queue for incoming messages
        - `sms_reader.py`: `SMSReader` — parses raw AT responses into SMS models
        - `sms_sender.py`: `SMSSender` — sends outgoing SMS via modem
        - `models.py`: Data models for SMS and modem operations
        - `consts.py`: Constants for timeouts and configurations
        - `utils.py`: Utility functions for SMS processing
