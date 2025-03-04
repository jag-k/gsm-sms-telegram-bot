from bot import SMSBot
from config import get_settings


settings = get_settings()

if __name__ == "__main__":
    SMSBot().run()
