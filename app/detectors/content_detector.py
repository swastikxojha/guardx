import re
TOXIC=["kill yourself","i will hurt you","go die","hate you"]
HARMFUL=["build a bomb","make a poison","steal credentials","exfiltrate secrets"]
def detect_content(text:str):
    low=text.lower(); toxic=[x for x in TOXIC if x in low]; harmful=[x for x in HARMFUL if x in low]
    return toxic,harmful
