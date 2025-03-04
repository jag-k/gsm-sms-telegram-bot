import re


SMS_HEADER_REGEX = re.compile(
    r"\+CMGL: (?P<id>\d+),"
    r'"(?P<status>[^"]*)",("(?P<sender>[^"]*)")?,("(?P<recipient>[^"]*)")?,("(?P<timestamp>[^"]*)")?'
)
CONTACT_REGEX = re.compile(r'\+CPBR: \d+,"(?P<number>[^"]+)",\d+,"(?P<name>[^"]+)"')
SIM_RANGE_REGEX = re.compile(r"\+CPBR: \((\d+)-(\d+)\)")
ASCII_SMS_LENGTH = 160  # Maximum length of a single SMS in characters
UNICODE_SMS_LENGTH = 70  # Maximum length of a single SMS in characters

# Unicode character threshold for detecting messages with non-ASCII characters
UNICODE_CHAR_THRESHOLD = 127

# Timeout and sizing constants
SMS_PROMPT_TIMEOUT = 3.0  # How long to wait for the SMS prompt character (>)
SMS_SEND_TIMEOUT = 5.0  # How long to wait for SMS send completion
SMS_PREVIEW_LENGTH = 30  # How many characters to show in logs for SMS preview
SMS_RESPONSE_PREVIEW = 50  # How many characters to show in logs for SMS response

# Command handling constants
MIN_SIGNIFICANT_DELAY = 0.05  # Minimum significant delay for command handling
BUFFER_SIZE = 1024  # Standard buffer size for serial reads
MIN_POLL_INTERVAL = 0.02  # Minimum polling interval for adaptive polling
MAX_POLL_INTERVAL = 0.25  # Maximum polling interval for adaptive polling
MIN_SLEEP_TIME = 0.01  # Minimum sleep time to avoid CPU spinning
SHORT_POLL_DELAY = 0.1  # Short delay for polling operations

# Real-time SMS monitoring settings
DEFAULT_SMS_CHECK_INTERVAL = 2.0  # Default interval (seconds) to check for new SMS
ACTIVE_MODE_TIMEOUT = 10  # Seconds to stay in active mode after message activity
INACTIVE_MODE_THRESHOLD = 30  # Seconds of inactivity before increasing interval
MIN_SLEEP_INTERVAL = 0.1  # Minimum sleep interval for monitoring loop
SIGNIFICANT_PROCESSING_TIME = 1.0  # Log warning if processing takes longer than this
OTP_KEYWORDS = ["code", "код", "otp", "пароль", "password"]  # Keywords for identifying OTP messages
