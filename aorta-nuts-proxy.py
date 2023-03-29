import requests
import json

BASE_URL = "https://example-api.com"

def introspect_access_token(access_token):
    """
    Introspects an access token to determine its validity.

    Args:
        access_token (str): The access token to introspect.

    Returns:
        dict: A dictionary containing information about the access token if it is valid.

    Raises:
        Exception: If the introspection request fails or the token is invalid.
    """
    endpoint = f"{BASE_URL}/internal/auth/v1/accesstoken/introspect"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.post(endpoint, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Introspection failed with status code {response.status_code}: {response.text}")

def request_access_token(client_id, client_secret, username, password):
    """
    Requests an access token using client credentials and user credentials.

    Args:
        client_id (str): The client ID to use for authentication.
        client_secret (str): The client secret to use for authentication.
        username (str): The username of the user to authenticate.
        password (str): The password of the user to authenticate.

    Returns:
        dict: A dictionary containing the access token if the request is successful.

    Raises:
        Exception: If the access token request fails.
    """
    endpoint = f"{BASE_URL}/internal/auth/v1/request-access-token"
    data = {"client_id": client_id, "client_secret": client_secret, "grant_type": "password", "username": username, "password": password}
    response = requests.post(endpoint, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Access token request failed with status code {response.status_code}: {response.text}")

def search_verifiable_credentials(access_token, issuer_id, subject_id=None, credential_type=None):
    """
    Searches for verifiable credentials that match the specified criteria.

    Args:
        access_token (str): The access token to use for authentication.
        issuer_id (str): The ID of the issuer to search for credentials from.
        subject_id (str, optional): The ID of the subject to search for credentials about. Defaults to None.
        credential_type (str, optional): The type of credential to search for. Defaults to None.

    Returns:
        dict: A dictionary containing the search results if the request is successful.

    Raises:
        Exception: If the verifiable credential search fails.
    """
    endpoint = f"{BASE_URL}/internal/vcr/v2/issuer/vc/search"
    headers = {"Authorization": f"Bearer {access_token}"}
    data = {"issuer_id": issuer_id}
    if subject_id:
        data["subject_id"] = subject_id
    if credential_type:
        data["type"] = credential_type
    response = requests.post(endpoint, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Verifiable credential search failed with status code {response.status_code}: {response.text}")
