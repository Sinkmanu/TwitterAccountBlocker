#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import re
import json
import urllib3
import urllib.parse
import sys
import argparse
import getpass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def getTokens():
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js' }
    url_base = "https://twitter.com/home?precache=1"
    r = requests.get(url_base, verify=False, headers=user_agent)
    soup = BeautifulSoup(r.text, "html.parser")
    js_with_bearer = ""
    for i in soup.find_all('link'):
        if i.get("href").find("/main") != -1:
            js_with_bearer = i.get("href")

    guest_token = re.findall(r'"gt=\d{19}', str(soup.find_all('script')[-1]), re.IGNORECASE)[0].replace("\"gt=","")
    print("[*] Js with Bearer token: %s" % js_with_bearer)
    print("[*] Guest token: %s" % guest_token)
    # Get Bearer token
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js' }
    r = requests.get(js_with_bearer, verify=False, headers=user_agent)
    bearer = re.findall(r'",[a-z]="(.*)",[a-z]="\d{8}"', r.text, re.IGNORECASE)[0].split("\"")[-1]
    print("[*] Bearer: %s" % bearer)

    rt_path = re.search(r'queryId:"(.+?)",operationName:"Retweeters"', r.text).group(1).split('"')[-1]
    viewer_path = re.search(r'queryId:"(.+?)",operationName:"Viewer"', r.text).group(1).split('"')[-1]

    print("[*] rt_url: %s" % rt_path)
    authorization_bearer = "Bearer %s" % bearer
    return authorization_bearer,guest_token,rt_path,viewer_path

def login(authorization_bearer, guest_token, username, password, email):
    # SSO login
    url_flow_1 = "https://twitter.com/i/api/1.1/onboarding/task.json?flow_name=login"
    url_flow_2 = "https://twitter.com/i/api/1.1/onboarding/task.json"
    # Flow 1
    data = {'' : ''}
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'X-Guest-Token' : guest_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer  }
    r = requests.post(url_flow_1, verify=False, headers=user_agent, data=json.dumps(data))
    print(r.text)
    flow_token = json.loads(r.text)['flow_token']
    print("[*] flow_token: %s" % flow_token)

    # Flow 2
    data = {'flow_token' : flow_token, "subtask_inputs" : []}
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'X-Guest-Token' : guest_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer  }
    r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data))
    flow_token = json.loads(r.text)['flow_token']
    print("[*] flow_token: %s" % flow_token)

    # Flow 3
    data = {"flow_token": flow_token ,"subtask_inputs":[{"subtask_id":"LoginEnterUserIdentifierSSOSubtask","settings_list":{"setting_responses":[{"key":"user_identifier","response_data":{"text_data":{"result":username}}}],"link":"next_link"}}]}
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'X-Guest-Token' : guest_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer  }
    r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data))
    flow_token = json.loads(r.text)['flow_token']
    print("[*] flow_token: %s" % flow_token)

    if (json.loads(r.text)['subtasks'][0]['subtask_id'] == "LoginEnterAlternateIdentifierSubtask"):
        # Sometimes login alternate because unusual LoginEnterUserIdentifierSSOSubtask
        data = {"flow_token": flow_token, "subtask_inputs":[{"subtask_id":"LoginEnterAlternateIdentifierSubtask","enter_text":{"text": email,"link":"next_link"}}]}
        user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'X-Guest-Token' : guest_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer  }
        r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data))
        flow_token = json.loads(r.text)['flow_token']
        print("[*] flow_token: %s" % flow_token)

    # Flow 4
    data = {"flow_token": flow_token ,"subtask_inputs":[{"subtask_id":"LoginEnterPassword","enter_password":{"password":password,"link":"next_link"}}]}
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'X-Guest-Token' : guest_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer  }
    r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data))
    flow_token = json.loads(r.text)['flow_token']
    user_id = json.loads(r.text)['subtasks'][0]['check_logged_in_account']['user_id']
    print("[*] flow_token: %s" % flow_token)
    print("[*] user_id: %s" % user_id)

    # Flow 5 (and get auth_token)
    data = {"flow_token":flow_token,"subtask_inputs":[{"subtask_id":"AccountDuplicationCheck","check_logged_in_account":{"link":"AccountDuplicationCheck_false"}}]}
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'X-Guest-Token' : guest_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer  }
    r = requests.post(url_flow_2, verify=False, headers=user_agent, data=json.dumps(data))
    flow_token = json.loads(r.text)['flow_token']
    auth_token = r.cookies['auth_token']
    print("[*] flow_token: %s" % flow_token)
    print("[*] auth_token: %s" % auth_token)
    return auth_token

def getCSRFToken(guest_token, auth_token, authorization_bearer):
    # Get CSRF Token
    payload = '{"withCommunitiesMemberships":true,"withCommunitiesCreation":true,"withSuperFollowsUserFields":true}'
    url_session_token = "https://twitter.com/i/api/graphql/%s/Viewer?variables=%s" % (viewer_path, urllib.parse.quote_plus(payload))
    cookie = "ct0=%s; auth_token=%s" % (guest_token, auth_token)
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'X-Guest-Token' : guest_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer, 'Cookie' : cookie  }
    r = requests.get(url_session_token, verify=False, headers=user_agent)
    csrf_token = r.cookies['ct0']
    print("[*] CSRF token: %s" % csrf_token)
    return csrf_token

def getRetweets(tweet_id, csrf_token, auth_token, authorization_bearer):
    # Get RT by id
    payload = '{"tweetId":"%s","count":20,"includePromotedContent":true,"withSuperFollowsUserFields":true,"withDownvotePerspective":false,"withReactionsMetadata":false,"withReactionsPerspective":false,"withSuperFollowsTweetFields":true,"__fs_dont_mention_me_view_api_enabled":false,"__fs_interactive_text":false,"__fs_responsive_web_uc_gql_enabled":false}' % tweet_id
    url_rt = "https://twitter.com/i/api/graphql/%s/Retweeters?variables=%s" % (rt_path, urllib.parse.quote_plus(payload))
    user_list = []
    cookie = "ct0=%s; auth_token=%s" % (csrf_token, auth_token)
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'x-guest-token' : guest_token , 'X-Csrf-Token' : csrf_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer, 'Cookie' : cookie  }
    r = requests.get(url_rt, verify=False, headers=user_agent)
    message = json.loads(r.text)['data']['retweeters_timeline']['timeline']['instructions'][0]['entries']
    for i in message:
        entryId = i['entryId']
        if (entryId.find("user") != -1):
            nick_user = i['content']['itemContent']['user_results']['result']['legacy']['screen_name']
            print("[*] Found: %s\t%s" % (entryId.replace("user-",""), nick_user))
            user_list.append(entryId.replace("user-",""))
        elif (entryId.find("cursor-bottom") != -1):
            next = i['content']['value']

    last = "dummy"
    while (next != last):
        last = next
        payload = '{"tweetId":"%s","count":20, "cursor":"%s","includePromotedContent":true,"withSuperFollowsUserFields":true,"withDownvotePerspective":false,"withReactionsMetadata":false,"withReactionsPerspective":false,"withSuperFollowsTweetFields":true,"__fs_dont_mention_me_view_api_enabled":false,"__fs_interactive_text":false,"__fs_responsive_web_uc_gql_enabled":false}' % (tweet_id, next)
        url_rt = "https://twitter.com/i/api/graphql/%s/Retweeters?variables=%s" % (rt_path, urllib.parse.quote_plus(payload))
        cookie = "ct0=%s; auth_token=%s" % (csrf_token, auth_token)
        user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'Referer' : 'https://twitter.com/sw.js', 'x-guest-token' : guest_token , 'X-Csrf-Token' : csrf_token, 'Content-Type' : 'application/json', 'Authorization' :  authorization_bearer, 'Cookie' : cookie  }
        r = requests.get(url_rt, verify=False, headers=user_agent)
        message = json.loads(r.text)['data']['retweeters_timeline']['timeline']['instructions'][0]['entries']
        for i in message:
            entryId = i['entryId']
            if (entryId.find("user") != -1):
                nick_user = i['content']['itemContent']['user_results']['result']['legacy']['screen_name']
                print("[*] Found: %s\t%s" % (entryId.replace("user-",""), nick_user))
                user_list.append(entryId.replace("user-",""))
            elif (entryId.find("cursor-bottom") != -1):
                next = i['content']['value']
    return user_list

def blockAccount(user_id, auth_token, csrf_token, authorization_bearer):
    url_block = "https://twitter.com/i/api/1.1/blocks/create.json"
    data = "user_id=%s" % user_id
    cookie = "ct0=%s; auth_token=%s" % (csrf_token, auth_token)
    user_agent = { 'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0', 'X-Csrf-Token' : csrf_token, 'Content-Type' : 'application/x-www-form-urlencoded', 'Authorization' :  authorization_bearer, 'Cookie' : cookie  }
    r = requests.post(url_block, verify=False, headers=user_agent, data=data)
    r_id = json.loads(r.text)['id_str']
    if (r_id == user_id):
        print("[+] User blocked: %s" % r_id)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Massively Twitter user blocker.')
    parser.add_argument('-u', '--user', dest='username', required=True, type=str, help='Twitter username')
    parser.add_argument('-p', '--password', dest='password', type=str, help='Password (if not enabled, it will be ask by a prompt)')
    parser.add_argument('-e', '--email', dest='email', type=str, help='Twitter email (optional)')
    parser.add_argument('-t', '--twitter-id', dest='tweet_id', type=str, help='Twitter id to block RT accounts')
    args = parser.parse_args()
    if ((args.username is not None) and (args.tweet_id is not None)):
        password = args.password
        if password is None:
            password = getpass.getpass(prompt='Password: ')
        authorization_bearer,guest_token,rt_path,viewer_path = getTokens()
        auth_token = login(authorization_bearer, guest_token, args.username, password, args.email)
        csrf_token = getCSRFToken(guest_token, auth_token, authorization_bearer)
        users_rt = getRetweets(args.tweet_id, csrf_token, auth_token, authorization_bearer)
        for i in users_rt:
            blockAccount(i, auth_token, csrf_token, authorization_bearer)
    else:
        parser.print_help()
