""" Client with helpers for similating vault usecases """

from typing import Any, Optional, List
import requests

VAULT_URL = "http://localhost:3001"


def auth_guard(fn):
    def auth_check(self, *args, **kwargs):
        if not self.token:
            raise Exception(
                "Attempted to call a protected method without authentication"
            )
        return fn(self, *args, **kwargs)

    return auth_check


def check_expected_status(
    response: requests.Response, expected_status_codes: Optional[list[int]]
):
    if expected_status_codes is None:
        return
    if response.status_code not in expected_status_codes:
        raise Exception(
            f"""Request failed:
            path={response.request.path_url}, body={response.request.body}
            {response.status_code} not in {expected_status_codes=} 
            {response.reason}, {response.json()}
            """
        )


class Actor:
    def __init__(self, vault_url: str, name: str, access_key: str, secret_key: str):
        self.name = name
        self.access_key = access_key
        self.secret_key = secret_key
        self.vault_url = vault_url
        self.token = None

    def authenticate(
        self, expected_statuses: Optional[list[int]] = None
    ) -> dict[str, str]:
        response = requests.post(
            f"{self.vault_url}/auth/token",
            auth=(self.access_key, self.secret_key),
        )
        check_expected_status(response, expected_statuses)
        self.token = response.json()["access_token"]
        return response.json()

    @auth_guard
    def create_principal(
        self,
        name: str,
        description: str,
        policies: List[str],
        expected_statuses: Optional[list[int]] = None,
    ) -> dict[str, str]:
        response = requests.post(
            f"{self.vault_url}/principals",
            json={"name": name, "description": description, "policies": policies},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    @auth_guard
    def create_collection(
        self, schema: dict[str, Any], expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.post(
            f"{self.vault_url}/collections",
            json=schema,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        check_expected_status(response, expected_statuses)

    @auth_guard
    def create_records(
        self,
        collection: str,
        records: List[dict[str, str]],
        expected_statuses: Optional[list[int]] = None,
    ) -> list[str]:
        response = requests.post(
            f"{self.vault_url}/collections/{collection}/records",
            json=records,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    @auth_guard
    def get_record(
        self,
        collection: str,
        record_id: str,
        fields: str,  # dict of params
        expected_statuses: Optional[list[int]] = None,
    ) -> dict[str, dict[str, str]]:
        response = requests.get(
            f"{self.vault_url}/collections/{collection}/records/{record_id}",
            params={"fields": fields},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    @auth_guard
    def create_policy(
        self, policy: dict[str, str], expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.post(
            f"{self.vault_url}/policies",
            headers={"Authorization": f"Bearer {self.token}"},
            json=policy,
        )
        check_expected_status(response, expected_statuses)

    @auth_guard
    def get_policy(
        self, policy_id: str, expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.get(
            f"{self.vault_url}/policies/{policy_id}",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        check_expected_status(response, expected_statuses)
        return response.json()
