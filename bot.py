import json
import os
import html
from slack_sdk.oauth import AuthorizeUrlGenerator
from slack_sdk.oauth.installation_store import FileInstallationStore, Installation
from slack_sdk.oauth.state_store import FileOAuthStateStore
from slack_sdk.web import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.signature import SignatureVerifier

from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, make_response
from slackeventsapi import SlackEventAdapter

#Declare the env path
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

#Set up values
client = WebClient(token=os.environ['SLACK_BOT_TOKEN'])
client_id = os.environ['CLIENT_ID']
client_secret = os.environ['CLIENT_SECRET']
redirect_uri = os.environ['REDIRECT_URI']
print(redirect_uri)
CHANNEL_ID = 'C05EBEU3W5P'
BOT_ID = client.api_call('auth.test')['user_id']

#Issue and consume state parameter value on the server-side
state_store = FileOAuthStateStore(expiration_seconds=300, base_dir="./data")
#Persist installation data and lookup it by IDs
installation_store = FileInstallationStore(base_dir="./data")

#Build https://slack.com/oauth/v2/authorize with sufficient query parameters
authorization_url_generator = AuthorizeUrlGenerator(
    client_id = client_id,
    scopes=['app_mentions:read', 'chat:write', 'channels:history', 'channels:read', 'chat:write'],
    user_scopes=['search:read'],
    redirect_uri=redirect_uri
)

#Build the Flask app
app = Flask(__name__)

slack_event_adapter = SlackEventAdapter(os.environ['SLACK_SIGNING_SECRET'], '/slack/events', app)

#Start the OAuth flow
@app.route("/slack/install", methods=['GET'])
def oauth_start():
    print("Hi, start installing!")
    #Generate a random value and store it on the server-side
    state = state_store.issue()
    #https://slack.com/oauth/v2/authorize?state=(generated value)&client_id={client_id}&scope=app_mentions:read,chat:write&user_scope=search:read
    url = authorization_url_generator.generate(state)
    print(url)
    return f'<a href="{html.escape(url)}">' \
           f'<img alt=""Add to Slack"" height="40" width="139" src="https://platform.slack-edge.com/img/add_to_slack.png" srcset="https://platform.slack-edge.com/img/add_to_slack.png 1x, https://platform.slack-edge.com/img/add_to_slack@2x.png 2x" /></a>'


#Redirect URL
@app.route("/slack/oauth/callback", methods=['GET'])
def oauth_callback():
    print("Callback success")
    #Retrieve the auth code and state from the request params
    if "code" in request.args:
        #Verify the state parameter
        if state_store.consume(request.args["state"]):
            client = WebClient() #no prepared token needed for this
            #Complete the installation by calling oauth v2 access API method
            oauth_response = client.oauth_v2_access(
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                code=request.args["code"]
            )
            installed_enterprise = oauth_response.get("enterprise") or {}
            is_enterprise_install = oauth_response.get("is_enterprise_install")
            installed_team = oauth_response.get("team") or {}
            installer = oauth_response.get("authed_user") or {}
            incoming_webhook = oauth_response.get("incoming_webhook") or {}
            bot_token = oauth_response.get("access_token")

            #Note: oauth.v2.access doesn't include bot_id in response 
            bot_id = None
            enterprise_url = None
            if bot_token is not None:
                auth_test = client.auth_test(token = bot_token)
                bot_id = auth_test["bot_id"]
                if is_enterprise_install is True:
                    enterprise_url = auth_test.get("url")
            print(oauth_response)

            installation = Installation(
                app_id = oauth_response.get("app_id"),
                enterprise_id=installed_enterprise.get("id"),
                enterprise_name=installed_enterprise.get("name"),
                enterprise_url=enterprise_url,
                team_id=installed_team.get("id"),
                team_name=installed_team.get("name"),
                bot_token=bot_token,
                bot_id=bot_id,
                bot_user_id=oauth_response.get("bot_user_id"),
                bot_scopes=oauth_response.get("scope") or "",  # comma-separated string
                user_id=installer.get("id") or "",
                user_token=installer.get("access_token"),
                user_scopes=installer.get("scope") or "",  # comma-separated string
                incoming_webhook_url=incoming_webhook.get("url"),
                incoming_webhook_channel=incoming_webhook.get("channel"),
                incoming_webhook_channel_id=incoming_webhook.get("channel_id"),
                incoming_webhook_configuration_url=incoming_webhook.get("configuration_url"),
                is_enterprise_install=is_enterprise_install,
                token_type=oauth_response.get("token_type"),
            )

            # Store the installation
            installation_store.save(installation)

            return "Thanks for installing this app!"
        else:
            return make_response(f"Try the installation again (the state value is already expired)", 400)

    error = request.args["error"] if "error" in request.args else ""
    return make_response(f"Something is wrong with the installation (error: {html.escape(error)})", 400)

#Token Lookup
signing_secret = os.environ['SLACK_SIGNING_SECRET']
signature_verifier = SignatureVerifier(signing_secret=signing_secret)

@app.route("/slack/events", methods=['POST'])
def slack_app():
    print("Hi these are events")
    #Verify incoming requests from Slack
    #https://api.slack.com/authentication/verifying-requests-from-slack
    if not signature_verifier.is_valid(
        body=request.get_data(),
        timestamp=request.headers.get("X-Slack-Request-Timestamp") or "",
        signature=request.headers.get("X-Slack-Signature") or ""):
        return make_response("invalid request", 403)

    # Handle a slash command invocation
    if "command" in request.form \
        and request.form["command"] == "/open-modal":
        try:
            # in the case where this app gets a request from an Enterprise Grid workspace
            enterprise_id = request.form.get("enterprise_id")
            # The workspace's ID
            team_id = request.form["team_id"]
            # Lookup the stored bot token for this workspace
            bot = installation_store.find_bot(
                enterprise_id=enterprise_id,
                team_id=team_id,
            )
            bot_token = bot.bot_token if bot else None
            if not bot_token:
                # The app may be uninstalled or be used in a shared channel
                return make_response("Please install this app first!", 200)

            # Open a modal using the valid bot token
            client = WebClient(token=bot_token)
            trigger_id = request.form["trigger_id"]
            response = client.views_open(
                trigger_id=trigger_id,
                view={
                    "type": "modal",
                    "callback_id": "modal-id",
                    "title": {
                        "type": "plain_text",
                        "text": "Awesome Modal"
                    },
                    "submit": {
                        "type": "plain_text",
                        "text": "Submit"
                    },
                    "blocks": [
                        {
                            "type": "input",
                            "block_id": "b-id",
                            "label": {
                                "type": "plain_text",
                                "text": "Input label",
                            },
                            "element": {
                                "action_id": "a-id",
                                "type": "plain_text_input",
                            }
                        }
                    ]
                }
            )
            return make_response("", 200)
        except SlackApiError as e:
            code = e.response["error"]
            return make_response(f"Failed to open a modal due to {code}", 200)

    elif "payload" in request.form:
        # Data submission from the modal
        payload = json.loads(request.form["payload"])
        if payload["type"] == "view_submission" \
            and payload["view"]["callback_id"] == "modal-id":
            submitted_data = payload["view"]["state"]["values"]
            print(submitted_data)  # {'b-id': {'a-id': {'type': 'plain_text_input', 'value': 'your input'}}}
            # You can use WebClient with a valid token here too
            return make_response("", 200)

    # Indicate unsupported request patterns
    return make_response("", 404)

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
