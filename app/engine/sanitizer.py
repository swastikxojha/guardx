from app.detectors.pii_detector import detect_pii, sanitize
from app.core.config import settings
def sanitize_content(text, mode=None):
    mode=mode or settings.pii_mode
    matches=detect_pii(text)
    return sanitize(text,matches,mode), matches
