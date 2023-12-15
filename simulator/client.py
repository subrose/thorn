""" Client with helpers for similating vault usecases """

from typing import Any, Optional, List
import requests
import os
from pydantic import BaseModel

from wait import wait_for_api


class Policy(BaseModel):
    name: Optional[str] = None
    effect: str
    actions: List[str]
    resources: List[str]


def init_client(override_vault_url: Optional[str] = None) -> str:
    vault_url = (
        os.environ.get("THORN_URL", "http://localhost:3001")
        if override_vault_url is None
        else override_vault_url
    )
    wait_for_api(vault_url)
    return vault_url


def check_expected_status(
    response: requests.Response, expected_status_codes: Optional[list[int]]
):
    if expected_status_codes is None:
        return
    if response.status_code not in expected_status_codes:
        raise Exception(
            f"""Request failed
            path={response.request.path_url}, body={response.request.body}
            headers={response.request.headers}
            {response.status_code} not in {expected_status_codes=} 
            {response.reason}, {response.text}
            """
        )


class Actor:
    def __init__(self, vault_url: str, username: str, password: str):
        self.username = username
        self.password = password
        self.vault_url = vault_url

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
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def delete_principal(
        self,
        username: str,
        expected_statuses: Optional[list[int]] = None,
    ) -> None:
        response = requests.delete(
            f"{self.vault_url}/principals/{username}",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return

    def create_collection(
        self,
        schema: dict[str, Any],
        expected_statuses: Optional[list[int]] = None,
    ) -> None:
        response = requests.post(
            f"{self.vault_url}/collections",
            json=schema,
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)

    def update_collection(
        self,
        collection: str,
        schema: dict[str, Any],
        expected_statuses: Optional[list[int]] = None,
    ) -> None:
        response = requests.put(
            f"{self.vault_url}/collections/{collection}",
            json=schema,
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)

    def create_record(
        self,
        collection: str,
        record: dict[str, str],
        expected_statuses: Optional[list[int]] = None,
    ) -> str:
        response = requests.post(
            f"{self.vault_url}/collections/{collection}/records",
            json=record,
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def get_record(
        self,
        collection: str,
        record_id: str,
        return_formats: str,
        expected_statuses: Optional[list[int]] = None,
    ) -> dict[str, str]:
        response = requests.get(
            f"{self.vault_url}/collections/{collection}/records/{record_id}",
            params={"formats": return_formats},
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def search_records(
        self,
        collection: str,
        filters: dict[str, str],
        expected_statuses: Optional[list[int]] = None,
    ):
        response = requests.post(
            f"{self.vault_url}/collections/{collection}/records/search",
            json=filters,
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def delete_record(
        self,
        collection: str,
        record_id: str,
        expected_statuses: Optional[list[int]] = None,
    ) -> None:
        response = requests.delete(
            f"{self.vault_url}/collections/{collection}/records/{record_id}",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return

    def create_policy(
        self, policy: Policy, expected_statuses: Optional[list[int]] = None
    ) -> dict[str, str]:
        response = requests.post(
            f"{self.vault_url}/policies",
            auth=(self.username, self.password),
            json=policy.model_dump(),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def get_policy(
        self, policy_id: str, expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.get(
            f"{self.vault_url}/policies/{policy_id}",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def delete_policy(
        self, policy_id: str, expected_statuses: Optional[list[int]] = None
    ) -> None:
        response = requests.delete(
            f"{self.vault_url}/policies/{policy_id}",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return

    def tokenise(
        self,
        collection: str,
        record_id: str,
        field: str,
        field_format: str,
        expected_statuses: Optional[list[int]] = None,
    ) -> str:
        response = requests.post(
            f"{self.vault_url}/tokens",
            auth=(self.username, self.password),
            json={
                "collection": collection,
                "recordId": record_id,
                "field": field,
                "format": field_format,
            },
        )
        check_expected_status(response, expected_statuses)
        return response.json()

    def detokenise(
        self, token_id: str, expected_statuses: Optional[list[int]] = None
    ) -> dict:
        response = requests.get(
            f"{self.vault_url}/tokens/{token_id}",
            auth=(self.username, self.password),
        )
        check_expected_status(response, expected_statuses)
        return response.json()
