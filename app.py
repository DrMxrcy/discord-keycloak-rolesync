import logging
import os
import time
import threading

import discord
from keycloak import KeycloakAdmin

dt_fmt = '%Y-%m-%d %H:%M:%S'
formatter = logging.Formatter('[{asctime}] [{levelname:<8}] {name}: {message}', dt_fmt, style='{')

handler = logging.StreamHandler()
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

KeycloakClient = KeycloakAdmin(
    server_url=os.environ["KEYCLOAK_URL"],
    username=os.environ["KEYCLOAK_USERNAME"],
    password=os.environ["KEYCLOAK_PASSWORD"],
    realm_name=os.environ["KEYCLOAK_REALM"],
    user_realm_name=os.environ["KEYCLOAK_ADMIN_REALM"])

intents = discord.Intents.default()
intents.members = True

DiscordClient = discord.Client(intents=intents)

def sync_user_roles():
    groups = get_linked_groups(client=KeycloakClient)
    for group in groups:
        role = get_linked_role(client=DiscordClient, group=group)
        if not role:
            continue

        logger.info(f'Syncing Keycloak group {group["name"]} with Discord role {role.name}')
        group_members = get_group_members(client=KeycloakClient, group_id=group["id"])

        for discord_user in role.members:
            keycloak_user = KeycloakClient.get_users(
                query={"idpUserId": discord_user.id, "idpAlias": "discord"})

            if len(keycloak_user) == 0:
                continue

            if keycloak_user[0]["id"] in [user["id"] for user in group_members]:
                continue

            logger.info("Adding %s (%s) to Keycloak group %s" % (
                keycloak_user[0]["username"], discord_user.display_name, group["name"]))

            KeycloakClient.group_user_add(user_id=keycloak_user[0]["id"], group_id=group["id"])

        for keycloak_user in group_members:
            discord_id = get_discord_id(client=KeycloakClient, user_id=keycloak_user["id"])

            if discord_id not in [user.id for user in role.members]:
                discord_user = DiscordClient.get_guild(role.guild.id).get_member(discord_id)
                if discord_user:
                    logger.info("Removing %s (%s) from Keycloak group %s" % (
                        keycloak_user["username"], discord_user.display_name, group["name"]))

                KeycloakClient.group_user_remove(user_id=keycloak_user["id"], group_id=group["id"])

def get_linked_groups(client: KeycloakAdmin = None) -> list:
    page_start = 0
    page_size = 100
    all_groups = []

    groups = client.get_groups(
        query={"briefRepresentation": "false",
               "first": page_start,
               "max": page_size}
    )
    all_groups += groups

    while len(groups) == page_size:
        page_start += page_size
        groups = client.get_groups(
            query={"briefRepresentation": "false",
                   "first": page_start,
                   "max": page_size}
        )
        all_groups += groups

    valid_groups = []

    for group in all_groups:
        try:
            if group["attributes"]["discord-guild"] and group["attributes"]["discord-role"]:
                valid_groups.append(group)
        except KeyError:
            pass

    return valid_groups

def get_linked_role(client: discord.Client = None, group: dict = None) -> discord.Role | None:
    guild_id = int(group["attributes"]["discord-guild"][0])
    role_id = int(group["attributes"]["discord-role"][0])

    guild = client.get_guild(guild_id)
    if guild is None:
        return None

    role = guild.get_role(role_id)
    if role is None:
        return None

    return role

def get_group_members(client: KeycloakAdmin = None, group_id: str = None) -> list:
    page_start = 0
    page_size = 100
    members = []

    group_members = client.get_group_members(
        group_id=group_id,
        query={"first": page_start, "max": page_size}
    )
    members += group_members

    while len(group_members) == page_size:
        page_start += page_size
        group_members = client.get_group_members(
            group_id=group_id,
            query={"first": page_start, "max": page_size}
        )
        members += group_members

    return members

def get_discord_id(client: KeycloakAdmin = None, user_id: str = None) -> int:
    profile = client.get_user(user_id=user_id)
    discord_id = None

    for provider in profile["federatedIdentities"]:
        if provider["identityProvider"] == "discord":
            discord_id = provider["userId"]

    if not discord_id:
        raise Exception("Cannot find Discord username")

    return int(discord_id)

@DiscordClient.event
async def on_ready():
    logger.info(f'We have logged in as {DiscordClient.user}')
    try:
        sync_user_roles()
    except Exception as e:
        logger.error(f"Error during initial sync: {e}")

@DiscordClient.event
async def on_member_update(previous, current):
    if current.id == DiscordClient.user.id:
        return

    previous_roles = set(previous.roles)
    current_roles = set(current.roles)

    added_roles = current_roles.difference(previous_roles)
    removed_roles = previous_roles.difference(current_roles)

    if current_roles == previous_roles:
        return

    keycloak_user = KeycloakClient.get_users(
        query={"idpUserId": previous.id, "idpAlias": "discord"})

    if len(keycloak_user) == 0:
        return

    if len(added_roles) > 0:
        for role in added_roles:
            keycloak_group = KeycloakClient.get_groups(
                query={"q": "discord-role:%s" % role.id, "exact": "true"})

            if keycloak_group:
                logger.info('Adding %s (%s) to Keycloak group %s' % (
                    keycloak_user[0]["username"], current.display_name, keycloak_group[0]["name"]))

                KeycloakClient.group_user_add(user_id=keycloak_user[0]["id"], group_id=keycloak_group[0]["id"])

    if len(removed_roles) > 0:
        for role in removed_roles:
            keycloak_group = KeycloakClient.get_groups(
                query={"q": "discord-role:%s" % role.id, "exact": "true"})

            if keycloak_group:
                logger.info('Removing %s (%s) from Keycloak group %s' % (
                    keycloak_user[0]["username"], current.display_name, keycloak_group[0]["name"]))

                KeycloakClient.group_user_remove(user_id=keycloak_user[0]["id"], group_id=keycloak_group[0]["id"])

def periodic_sync():
    while True:
        logger.info("Running periodic sync...")
        try:
            sync_user_roles()
        except Exception as e:
            logger.error(f"Error during periodic sync: {e}")
        time.sleep(30)  # Sync interval, adjust as needed

if __name__ == "__main__":
    threading.Thread(target=periodic_sync).start()
    DiscordClient.run(token=os.environ["DISCORD_BOT_TOKEN"], log_handler=handler, log_formatter=formatter)
