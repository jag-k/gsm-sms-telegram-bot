# Configuration

Here you can find all available configuration options using ENV variables.

## Settings

Settings for the SMS Telegram Bot.

All settings can be overridden with environment variables.

| Name        | Type                                                                                                  | Default  | Description   | Example  |
|-------------|-------------------------------------------------------------------------------------------------------|----------|---------------|----------|
| `LOG_LEVEL` | `"trace"` \| `"debug"` \| `"info"` \| `"notice"` \| `"warn"` \| `"warning"` \| `"error"` \| `"fatal"` | `"info"` | Logging level | `"info"` |

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

Settings for access to the GSM SMS gateway.

**Environment Prefix**: `MODEM__`

| Name                    | Type         | Default                    | Description                                                | Example                    |
|-------------------------|--------------|----------------------------|------------------------------------------------------------|----------------------------|
| `MODEM__GATEWAY_URL`    | `AnyHttpUrl` | `"http://127.0.0.1:8000/"` | Base URL of gsm-sms-gateway                                | `"http://127.0.0.1:8000/"` |
| `MODEM__DEFAULT_REGION` | `string`     | `"US"`                     | Default region code for phone numbers without country code | `"US"`                     |

### LogfireSettings

Settings for Logfire.

**Environment Prefix**: `LOGFIRE__`

| Name                   | Type                        | Default   | Description                               | Example   |
|------------------------|-----------------------------|-----------|-------------------------------------------|-----------|
| `LOGFIRE__TOKEN`       | `string` \| `null`          | `null`    | Logfire API token                         | `null`    |
| `LOGFIRE__ENVIRONMENT` | `"local"` \| `"production"` | `"local"` | Logfire environment name                  | `"local"` |
| `LOGFIRE__REVISION`    | `string`                    | `"main"`  | Git revision. Branch name or commit hash. | `"main"`  |
