import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import requests
import json
from os.path import exists

load_dotenv()

#############################
#       Configuration       #
#############################

DUMMY_BASE_URL = os.getenv("DUMMY_BASE_URL")
LOGIN_URL = f"{DUMMY_BASE_URL}/auth/login"
REFRESH_URL = f"{DUMMY_BASE_URL}/auth/refresh"
PROTECTED_URL = f"{DUMMY_BASE_URL}/auth/me"
TOKEN_STORE = "./token_store.json"
print(os.path.abspath(TOKEN_STORE))

##############################
#      Token management      #
##############################

def load_tokens():
    if not exists(TOKEN_STORE) or os.path.getsize(TOKEN_STORE) == 0:
        # Fichier inexistant ou vide
        return {
            "access_token": None,
            "refresh_token": None,
            "access_token_expiry": None,
            "refresh_token_expiry": None,
        }

    try:
        with open(TOKEN_STORE, "r", encoding="utf-8") as f:
            token_data = json.load(f)

        def parse_date(date_str):
            return datetime.fromisoformat(date_str) if date_str else None

        return {
            "access_token": token_data.get("access_token"),
            "refresh_token": token_data.get("refresh_token"),
            "access_token_expiry": parse_date(token_data.get("access_token_expiry")),
            "refresh_token_expiry": parse_date(token_data.get("refresh_token_expiry")),
        }

    except (json.JSONDecodeError, ValueError, KeyError) as e:
        print(f"⚠️ Erreur lors du chargement des tokens : {e}")
        return {
            "access_token": None,
            "refresh_token": None,
            "access_token_expiry": None,
            "refresh_token_expiry": None,
        }

def save_tokens(tokens, access_expires_in=3600, refresh_expires_in=86400):
    now = datetime.now()

    # Chargement tokens actuels pour récupérer les "old" actuels
    try:
        with open(TOKEN_STORE, "r", encoding="utf-8") as f:
            old_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        old_data = {}

    # On récupère les tokens actuels pour les sauvegarder comme "old"
    old_access_token = old_data.get("access_token")
    old_refresh_token = old_data.get("refresh_token")
    old_access_expiry = old_data.get("access_token_expiry")
    old_refresh_expiry = old_data.get("refresh_token_expiry")

    access_expiry_time = (now + timedelta(seconds=access_expires_in)).isoformat()
    refresh_expiry_time = (now + timedelta(seconds=refresh_expires_in)).isoformat()

    data = {
        "id": "tokens",
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "access_token_expiry": access_expiry_time,
        "refresh_token_expiry": refresh_expiry_time,

        # On stocke les anciens tokens et leurs dates d'expiration
        "old_access_token": old_access_token,
        "old_refresh_token": old_refresh_token,
        "old_access_token_expiry": old_access_expiry,
        "old_refresh_token_expiry": old_refresh_expiry,
    }

    with open(TOKEN_STORE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)  # Format lisible

def is_token_expired():
    expiry = load_tokens().get("access_token_expiry")
    return not expiry or datetime.now() >= expiry

def is_refresh_token_expired():
    expiry = load_tokens().get("refresh_token_expiry")
    return not expiry or datetime.now() >= expiry

##############################
#       Authentication       #
##############################

def login(username, password):
    response = requests.post(LOGIN_URL, json={"username": username, "password": password})
    if response.status_code == 200:
        tokens = response.json()
        save_tokens(
            {
                "access_token": tokens.get("accessToken") or tokens.get("token"),
                "refresh_token": tokens.get("refreshToken") or "dummy_refresh_token"
            },
            tokens.get("expires_in", 3600),
            tokens.get("refresh_expires_in", 86400)
        )
        print("✅ Connexion réussie.")
    else:
        raise Exception(f"❌ Login échoué : {response.status_code} {response.text}")

def refresh_access_token():
    tokens = load_tokens()
    refresh_token = tokens.get("refresh_token")
    if not refresh_token or is_refresh_token_expired():
        raise Exception("Refresh token expiré ou manquant.")

    response = requests.post(REFRESH_URL, json={"refreshToken": refresh_token})
    if response.status_code == 200:
        new_tokens = response.json()
        save_tokens(
            {
                "access_token": new_tokens.get("accessToken") or new_tokens.get("token"),
                "refresh_token": new_tokens.get("refreshToken") or refresh_token
            },
            new_tokens.get("expires_in", 3600),
            new_tokens.get("refresh_expires_in", 86400)
        )
        print("🔄 Access token rafraîchi.")
    else:
        raise Exception(f"❌ Échec du refresh : {response.status_code} {response.text}")

##############################
#   API call personal data   #
##############################

def get_personal_data():
    tokens = load_tokens()
    access_token = tokens.get("access_token")
    headers = {"Authorization": f"Bearer {access_token}"}

    response = requests.get(PROTECTED_URL, headers=headers)
    if response.status_code == 200:
        print("🔐 Données protégées :")
        print(response.json())
    elif response.status_code == 401:
        print("⏰ Token expiré. Tentative de refresh...")
        try:
            refresh_access_token()
            get_personal_data()
        except Exception as e:
            print(f"🔐 Tentative de login : {e}")
            login(os.getenv("DUMMY_USERNAME"), os.getenv("DUMMY_PASSWORD"))
            get_personal_data()
    else:
        print(f"❌ Erreur inconnue : {response.status_code} {response.text}")

#############################
#        Entry point        #
#############################

if __name__ == "__main__":
    tokens = load_tokens()
    if not tokens["access_token"] or not tokens["refresh_token"]:
        print("🟠 Aucun token trouvé. Connexion...")
        login(os.getenv("DUMMY_USERNAME"), os.getenv("DUMMY_PASSWORD"))
    elif is_refresh_token_expired():
        print("🔴 Refresh token expiré. Reconnexion requise.")
        login(os.getenv("DUMMY_USERNAME"), os.getenv("DUMMY_PASSWORD"))
    elif is_token_expired():
        print("⏰ Access token expiré. Rafraîchissement...")
        try:
            refresh_access_token()
        except Exception as e:
            print(e)
            login(os.getenv("DUMMY_USERNAME"), os.getenv("DUMMY_PASSWORD"))
    else:
        print("🟢 Tokens valides.")
    get_personal_data()
