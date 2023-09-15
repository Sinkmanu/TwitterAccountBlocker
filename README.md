# TwitterAccountBlocker
Python script which help to block Twitter users massively.

> [!IMPORTANT]
> Twitter (now X) is a website with private code, if they make changes probably this tool will not work, in the blog post I explain how is the process to create a tool like this.  Last update (and working): 15/09/2023

## Usage

```python
python3 TwitterAccountBlocker.py -u <username> -t <tweet id>
```



## Options
```python
 ./TwitterAccountBlocker.py -h

usage: TwitterAccountBlocker.py [-h] -u USERNAME [-p PASSWORD] [-e EMAIL]
                                [-t TWEET_ID]

Massively Twitter user blocker.

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        Twitter username
  -p PASSWORD, --password PASSWORD
                        Password (if not enabled, it will be ask by a prompt)
  -e EMAIL, --email EMAIL
                        Twitter email (optional)
  -t TWEET_ID, --twitter-id TWEET_ID
                        Twitter id to block RT accounts
```



## Requirements

- requests

- BeautifulSoup4

- Python3

  

## Hacking

This tool is the result of a couple of hours researching how the login works and how to block users. It can be significantly improved, e.g. Creating the functionality to import a list of users in order to block them (like the old functionality which is currently not available in Twitter https://help.twitter.com/en/using-twitter/advanced-twitter-block-options) 

An explanation about how this tool have been developed can be found at https://unam.re/blog/developing-your-own-twitter-api
