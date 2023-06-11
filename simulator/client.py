""" Client with helpers for similating vault usecases """

from typing import List
import requests

VAULT_URL = "http://localhost:3000"


class Actor:
    def __init__(self, vault_url: str, name: str, access_key: str, secret_key: str):
        self.name = name
        self.access_key = access_key
        self.secret_key = secret_key
        self.vault_url = vault_url
        self.token = None

    def auth_guard(fn, **args):
        def auth_check(self, *args, **kwargs):
            if not self.token:
                raise Exception(
                    "Attempted to call a protected method without authentication"
                )
            return fn(self, *args, **kwargs)

        return auth_check

    def authenticate(self):
        response = requests.post(
            f"{self.vault_url}/auth/token",
            auth=(self.access_key, self.secret_key),
        )
        if response.status_code == 200:
            self.token = response.json()["access_token"]
            return True
        print("Authentication failed", response.status_code, response.text)
        return None

    @auth_guard
    def create_principal(self, name: str, description: str, policies: list[str]):
        response = requests.post(
            f"{self.vault_url}/principals",
            json={"name": name, "description": description, "policies": policies},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        if response.status_code == 201:
            return response.json()
        print("Create principal failed", response.status_code, response.text)
        return None

    @auth_guard
    def create_collection(self, schema: dict):
        response = requests.post(
            f"{self.vault_url}/collections",
            json=schema,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        if response.status_code == 201:
            return True
        print("Create collection failed", response.status_code, response.text)
        return None

    @auth_guard
    def create_records(self, collection: str, record: List[dict]):
        response = requests.post(
            f"{self.vault_url}/collections/{collection}/records",
            json=record,
            headers={"Authorization": f"Bearer {self.token}"},
        )
        if response.status_code == 201:
            return response.json()
        print("Create record failed", response.status_code, response.text)
        return None

    @auth_guard
    def get_record(self, collection: str, record_id: str):
        response = requests.get(
            f"{self.vault_url}/collections/{collection}/records/{record_id}",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        if response.status_code == 200:
            return response.json()
        print("Get record failed", response.status_code, response.text)
        return None

    @auth_guard
    def create_policy(self, policy: dict):
        response = requests.post(
            f"{self.vault_url}/policies",
            headers={"Authorization": f"Bearer {self.token}"},
            json=policy,
        )
        if response.status_code == 201:
            return response.json()
        print("Create policy failed", response.status_code, response.text)
        return None

    @auth_guard
    def get_policy(self, policy_id: str):
        response = requests.get(
            f"{self.vault_url}/policies/{policy_id}",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        if response.status_code == 200:
            return response.json()
        print("Get policy failed", response.status_code, response.text)
        return None


if __name__ == "__main__":
    admin = Actor(VAULT_URL, "admin", "admin", "admin")
    admin.authenticate()

    res = admin.create_collection(
        {
            "name": "users",
            "fields": {
                "fname": {"type": "string", "indexed": True},
                "lname": {"type": "string", "indexed": True},
            },
        }
    )
    rec = admin.create_records(
        "users",
        [
            {"fname": "John", "lname": "Doe"},
            {"fname": "Alex", "lname": "Doe"},
            {"fname": "Mike", "lname": "Doe"},
        ],
    )
    pp = admin.create_policy(
        policy={
            "policy_id": "alice-read-users-records",
            "effect": "allow",
            "action": "read",
            "resource": "collections/users/records/",
        }
    )
    pp = admin.create_policy(
        policy={
            "policy_id": "alice-read-users-collection",
            "effect": "allow",
            "action": "read",
            "resource": "collections/users/",
        }
    )

    # record = admin.get_record("users", rec[0])
    # print(record)

    alice_res = admin.create_principal(
        "alice", "Alice", ["alice-read-users-records", "alice-read-users-collection"]
    )
    alice = Actor(
        VAULT_URL, "alice", alice_res["access_key"], alice_res["access_secret"]
    )
    alice.authenticate()

    alice.get_record("users", rec[0])

    # rec = alice.get_record("users", rec[0])
    # print(rec)
