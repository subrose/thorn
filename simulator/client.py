""" Client with helpers for similating vault usecases """

from typing import Any, Optional, List
import requests


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
            {response.reason}, {response.text}
            """
        )


class Actor:
    def __init__(self, vault_url: str, username: str, password: str):
        self.username = username
        self.password = password
        self.vault_url = vault_url
        self.token = None

    def authenticate(
        self, expected_statuses: Optional[list[int]] = None
    ) -> dict[str, str]:
        response = requests.post(
            f"{self.vault_url}/auth/token",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        self.token = response.json()["access_token"]
        return response.json()

    @auth_guard
    def create_principal(
        self,
        username: str,
        password: str,
        description: str,
        policies: List[str],
        expected_statuses: Optional[list[int]] = None,
    ) -> dict[str, str]:
        response = requests.post(
            f"{self.vault_url}/principals",
            json={
                "username": username,
                "password": password,
                "description": description,
                "policies": policies,
            },
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
        format: str,  # dict of params
        expected_statuses: Optional[list[int]] = None,
    ) -> dict[str, dict[str, str]]:
        response = requests.get(
            f"{self.vault_url}/collections/{collection}/records/{record_id}/{format}",
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
