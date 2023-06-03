import base64
import time
import requests
import os
from logo import Logo
from dotenv import load_dotenv
load_dotenv()
VIRUS_TOTAL_API = "YOUR API GOES HERE" ### https://developers.virustotal.com/reference/overview
SENDER_CHECKER_API = "YOUR API GOES HERE" ### https://www.abstractapi.com/api/email-verification-validation-api
print(Logo.logo)
sender_address = input("Let's start first by checking sender's email. Input email address here: ")
email_content = input('Enter the email content here: ')
link_content = input('If email contains any link enter it here, if not just press enter')
link_bytes = link_content.encode('ascii')
link_encoded = base64.urlsafe_b64encode('https://linkdelivery.vmware.com/ls/click'.encode()).decode().strip("=")
positive_impact = 0

def check_sender(sender):
    response = requests.get(f"https://emailvalidation.abstractapi.com/v1/?api_key={os.getenv('SENDER_CHECKER_API')}&email={sender}")
    quality_score  = response.json()['quality_score']
    return quality_score


def check_link(link):
    global positive_impact
    positive_impact +=1
    url = f"https://www.virustotal.com/api/v3/urls/{link}"
    headers = {
        'x-apikey': os.getenv('VIRUS_TOTAL_API')
    }
    response=requests.get(url,headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data["data"]["attributes"]["last_analysis_stats"]["harmless"] > 5:
            print("URL is valid and not flagged as malicious.")
        else:
            print("URL is potentially malicious.")
    else:
        print('Invalid URL')

def check_grammar(text):
    url = "https://api.languagetool.org/v2/check"
    payload = {
        "text": text,
        "language": "en-US",
        "disabledRules": "UPPERCASE_SENTENCE_START",
        "enabledOnly": "false"
    }
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Request failed with status code: {response.status_code}")

print('Analysing the email address....')
time.sleep(3)
email_address_score = check_sender(sender_address)
if float(email_address_score) > 0.8:
    positive_impact+=1
    print('Email can be trusted')
else:
    print('Email is not trustful')


print('Analysing the link....')
time.sleep(3)
check_link(link_encoded)

grammar_check = check_grammar(email_content)
matches = grammar_check.get('matches', [])
print('Analysing the email content...')
time.sleep(3)
if matches:
    print(f"Grammar errors found: {len(matches)}")
    if len(matches) >= 3:
        print('CRITICAL WARNING about bad grammar! More than 3 grammar errors found!')
else:
    positive_impact +=1
    print('No grammar errors found!')


if positive_impact == 3:
    print('This email is most likely legit')
elif positive_impact >=2:
    print('This email is not 100% trustworthy, be careful!')
else:
    print('Delete this email!')