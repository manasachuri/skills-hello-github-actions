import requests
import base64
import json
import os
import nacl.public
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

API_VERSION = "2022-11-28"

def get_env_config(env_name):
    return {
        "rancher_url": os.environ["RANCHER_URL"],
        "github_token": os.environ["GITHUB_TOKEN"],
        "repo": os.environ["REPO"],
        "workflow_file": os.environ["WORKFLOW_FILE"],
        "secret_name": "RANCHER_ACCESS_SECRET_VALUE",
        "github_environment": env_name
    }

def generate_rancher_api_key(rancher_url, rancher_token):
    headers = {
        "Authorization": f"Bearer {rancher_token}",
        "Content-Type": "application/json"
    }
    payload = {"description": "Rotated API key", "type": "token"}
    response = requests.post(f"{rancher_url}/v3/token", headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

def delete_rancher_token(rancher_url, rancher_token, token_id):
    headers = {
        "Authorization": f"Bearer {rancher_token}",
        "Content-Type": "application/json"
    }
    url = f"{rancher_url}/v3/token/{token_id}"
    response = requests.delete(url, headers=headers)
    if response.status_code == 204:
        logging.info(f"Old token {token_id} deleted successfully.")
    else:
        logging.warning(f"Failed to delete old token {token_id}: {response.status_code} - {response.text}")

def delete_current_rancher_token(rancher_url, rancher_token, access_key):
    headers = {
        "Authorization": f"Bearer {rancher_token}",
        "Content-Type": "application/json"
    }
    response = requests.get(f"{rancher_url}/v3/token", headers=headers)
    response.raise_for_status()
    tokens = response.json()["data"]
    for token in tokens:
        if token["id"] == access_key:
            logging.info(f"Deleting old token with ID: {token['id']}")
            delete_rancher_token(rancher_url, rancher_token, token["id"])
            return
    logging.warning("Token with description 'Rotated API key' not found.")

def get_github_env_public_key(repo, environment, github_token):
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }
    url = f"https://api.github.com/repos/{repo}/environments/{environment}/secrets/public-key"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def encrypt_secret(public_key: str, secret_value: str) -> str:
    public_key_bytes = base64.b64decode(public_key)
    sealed_box = nacl.public.SealedBox(nacl.public.PublicKey(public_key_bytes))
    encrypted = sealed_box.encrypt(secret_value.encode())
    return base64.b64encode(encrypted).decode()

def update_github_env_secret(repo, environment, secret_name, encrypted_value, key_id, github_token):
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }
    url = f"https://api.github.com/repos/{repo}/environments/{environment}/secrets/{secret_name}"
    payload = {
        "encrypted_value": encrypted_value,
        "key_id": key_id
    }
    response = requests.put(url, headers=headers, json=payload)
    if response.status_code not in (201, 204):
        raise requests.HTTPError(f"{response.status_code} Error updating env secret: {response.text}")

def trigger_workflow(repo, workflow_file, github_token):
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": API_VERSION,
    }
    payload = {"ref": "main"}
    url = f"https://api.github.com/repos/{repo}/actions/workflows/{workflow_file}/dispatches"
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()

def main():
    try:
        target_env = os.environ.get("TARGET_ENVIRONMENT", "Sandbox")
        config = get_env_config(target_env)

        rancher_creds = json.loads(os.environ["RANCHER_ACCESS_SECRET_VALUE"])
        access_key = rancher_creds["access_key"]
        secret_key = rancher_creds["secret_key"]
        rancher_token = f"{access_key}:{secret_key}"

        new_api_key = generate_rancher_api_key(config["rancher_url"], rancher_token)
        full_token = new_api_key["token"]
        access_key, secret_key = full_token.split(":")
        new_api_secret = {"access_key": access_key, "secret_key": secret_key}

        public_key_info = get_github_env_public_key(config["repo"], config["github_environment"], config["github_token"])
        encrypted_value = encrypt_secret(public_key_info["key"], json.dumps(new_api_secret))
        update_github_env_secret(config["repo"], config["github_environment"], config["secret_name"], encrypted_value, public_key_info["key_id"], config["github_token"])

        delete_current_rancher_token(config["rancher_url"], rancher_token, rancher_creds["access_key"])
        trigger_workflow(config["repo"], config["workflow_file"], config["github_token"])

        logging.info("✅ Rancher API key rotated, GitHub environment secret updated, and workflow triggered.")
    except Exception as e:
        logging.critical(f"Unhandled exception: {e}")
        raise

if __name__ == "__main__":
    main()
