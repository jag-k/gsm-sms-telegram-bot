# GSM SMS Telegram Bot Development Guide

## Development Commands

- Install dependencies: `uv sync`
- Lint and format code: `uv run ruff check src/ --fix && ruff format src/`
- Type check: `uv run ty check src/`
- Run checks (all): `uv run pre-commit run --all-files`

> **Note:** The bot requires a running `gsm-sms-gateway`; it never opens the physical modem itself.
> End-to-end modem behavior can only be tested on the Raspberry Pi after the gateway image is deployed there.
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
- Keep the bot as a REST/SSE consumer; serial and AT behavior belongs to `gsm-sms-gateway` and `gsm-sms`
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
    - `gsm_sms.client`: optional package client used for gateway REST/SSE
