import re


SMS_HEADER_REGEX = re.compile(
    r"\+CMGL: (?P<id>\d+),"
    r'"(?P<status>[^"]*)",("(?P<sender>[^"]*)")?,("(?P<recipient>[^"]*)")?,("(?P<timestamp>[^"]*)")?'
)
CONTACT_REGEX = re.compile(r'\+CPBR: \d+,"(?P<number>[^"]+)",\d+,"(?P<name>[^"]+)"')
SIM_RANGE_REGEX = re.compile(r"\+CPBR: \((\d+)-(\d+)\)")
ASCII_SMS_LENGTH = 160  # Maximum length of a single SMS in characters
UNICODE_SMS_LENGTH = 70  # Maximum length of a single SMS in characters
