# Configuration

Here you can find all available configuration options using ENV variables.

## Settings

Settings for the SMS Telegram Bot.

All settings can be overridden with environment variables.

### BotSettings

Settings for the SMS Telegram Bot.

**Environment Prefix**: `BOT__`

| Name                         | Type      | Default                                    | Description                                                                               | Example                                    |
|------------------------------|-----------|--------------------------------------------|-------------------------------------------------------------------------------------------|--------------------------------------------|
| `BOT__TOKEN`                 | `string`  | *required*                                 | Telegram Bot API token                                                                    |                                            |
| `BOT__ALLOWED_USER_ID`       | `integer` | *required*                                 | Telegram user ID that can interact with the bot                                           |                                            |
| `BOT__RECENT_MESSAGES_COUNT` | `integer` | `10`                                       | Number of recent messages to show with `/start` command                                   | `10`                                       |
| `BOT__PERSISTENCE_FILE`      | `Path`    | `"<project_dir>/data/sms_bot_data.pickle"` | File to store bot persistence data. In Docker, the default is `/data/sms_bot_data.pickle` | `"<project_dir>/data/sms_bot_data.pickle"` |

### ModemSettings

Settings for the GSM Modem.

**Environment Prefix**: `MODEM__`

| Name                            | Type      | Default          | Description                                                | Example          |
|---------------------------------|-----------|------------------|------------------------------------------------------------|------------------|
| `MODEM__MODEM_PORT`             | `string`  | `"/dev/ttyUSB0"` | Serial port for the GSM modem                              | `"/dev/ttyUSB0"` |
| `MODEM__BAUD_RATE`              | `integer` | `115200`         | Baud rate for the GSM modem                                | `115200`         |
| `MODEM__DEFAULT_REGION`         | `string`  | `"US"`           | Default region code for phone numbers without country code | `"US"`           |
| `MODEM__MERGE_MESSAGES_TIMEOUT` | `integer` | `10`             | Timeout in seconds for merging messages                    | `10`             |
| `MODEM__CHECK_RATE`             | `integer` | `3`              | Rate in seconds to check for new messages                  | `3`              |
