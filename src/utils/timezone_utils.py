import pytz
from datetime import datetime

def get_chicago_tz():
    """Get the Chicago timezone object"""
    return pytz.timezone('America/Chicago')

def utc_to_chicago(utc_dt):
    """Convert UTC datetime to Chicago time"""
    if not utc_dt.tzinfo:
        utc_dt = pytz.utc.localize(utc_dt)
    return utc_dt.astimezone(get_chicago_tz())

def chicago_now():
    """Get current time in Chicago timezone"""
    return datetime.now(get_chicago_tz())

def format_chicago_datetime(dt):
    """Format datetime in Chicago timezone with proper format"""
    chicago_time = utc_to_chicago(dt)
    return chicago_time.strftime('%Y-%m-%d %H:%M:%S %Z')

def parse_iso_to_chicago(iso_string: str) -> datetime:
    """Parse an ISO format string to Chicago time"""
    dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
    return utc_to_chicago(dt) 