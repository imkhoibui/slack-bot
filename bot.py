import slack_sdk
import os
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask
from slackeventsapi import SlackEventAdapter

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
slack_event_adapter = SlackEventAdapter(os.environ['SLACK_SIGNING_SECRET'], '/slack/events', app)
client = slack_sdk.WebClient(token=os.environ['SLACK_BOT_TOKEN'])
CHANNEL_ID = 'C05EBEU3W5P'
BOT_ID = client.api_call('auth.test')['user_id']

@slack_event_adapter.on('message')
def message(payload):
    print(payload)
    event = payload.get('event', {})
    channel_id = event.get('channel')
    user_id = event.get('user')
    text = event.get('text')

    if BOT_ID != user_id and CHANNEL_ID == channel_id:
        client.chat_postMessage(channel=channel_id, text = text)

if __name__ == "__main__":
    app.run(debug=True)
