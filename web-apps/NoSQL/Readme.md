
# What are the use cases for this script ? 

Script helps to exploit time based Server-side JavaScript code injection in NoSQL databases.
Peresiquites are: 

1) Confirmation that application is injectable 
2) Name of field to be extracted 
3) Valid username or other anchor 

Structure of NoSQL queries are not as strict as in MySQL so there might be a need of making adjustments in 
query itself before using this script.

For more information on enumerating fieldnames and field values can be found in following article 
https://portswigger.net/web-security/nosql-injection

## Configuring Treshold and sleep 

This values must be always customized to the target. Threshold determines where sleep vaule (True) was triggered in payload.  If the payload evaluates to a False condition (no sleep), the response takes approximately 1 second — set the sleep value high enough to safely distinguish True from False. In that case, setting sleep to 3 seconds and treshold to 3 seems like right choice.

## Usage & License

**Disclaimer:** This tool is provided for educational and authorized security testing purposes only. 

By using this script, you acknowledge that:
- You have explicit written permission to test the target systems
- You understand the legal implications of unauthorized access to computer systems
- You will only use this tool for legitimate penetration testing, security research, or CTF competitions
- You accept full responsibility for your actions

**The author holds no liability for:**
- Unauthorized access or damage caused by misuse of this tool
- Legal consequences resulting from improper use
- Any harm caused by using this script on systems without proper authorization

This tool is intended for use by security professionals in controlled environments with proper authorization. Unauthorized access to computer systems is illegal in most jurisdictions.