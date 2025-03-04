import logging

import logfire

from bot import SMSBot, settings


logging.basicConfig(handlers=[logfire.LogfireLoggingHandler()])
logging.getLogger("bot").setLevel(logging.DEBUG)
logging.getLogger("sms_reader").setLevel(logging.DEBUG)

logfire.configure(
    local=settings.logfire.environment == "local",
    send_to_logfire="if-token-present",
    token=settings.logfire.token,
    environment=settings.logfire.environment,
    code_source=logfire.CodeSource(
        repository="https://github.com/jag-k/gsm-sms-telegram-bot",
        revision="main",
    ),
)
logfire.instrument_system_metrics()

if __name__ == "__main__":
    SMSBot().run()
