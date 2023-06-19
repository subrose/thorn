import random

from locust import FastHttpUser, between, events, task
from locust.runners import MasterRunner
import requests


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    res = requests.post(
        f"{environment.host}/auth/token",
        auth=("admin", "admin"),
    )
    try:
        jwt_token = res.json()["access_token"]
    except KeyError:
        print("LOGIN FAILED", res.status_code, res.text)
        exit(1)
    # Create a collection
    collection_json = {
        "name": "customers",
        "fields": {
            "fname": {"type": "string", "indexed": True},
            "lname": {"type": "string", "indexed": True},
        },
    }
    requests.post(
        f"{environment.host}/collections",
        json=collection_json,
        headers={"Authorization": f"Bearer {jwt_token}"},
    )
    print("INIT COMPLETE")


class AdminUser(FastHttpUser):
    wait_time = between(0.0001, 0.0001)
    jwt_token = None
    records = []
    max_records = 100

    @task(2)
    def create_records(self):
        if len(self.records) >= self.max_records:
            return
        i = random.randint(1, 100)
        record_json = [{"fname": f"John{i}", "lname": f"Doe{i}"}]
        res = self.client.post(
            "/collections/customers/records",
            json=record_json,
            headers={"Authorization": f"Bearer {self.jwt_token}"},
        )
        if res.status_code == 201:
            self.records.extend(res.json())
        else:
            print("CREATE RECORDS FAILED", res.status_code, res.text)

    @task(3)
    def get_records(self):
        if len(self.records) > 0:
            record_id = random.choice(self.records)
            self.client.get(
                f"/collections/customers/records/{record_id}",
                headers={"Authorization": f"Bearer {self.jwt_token}"},
            )

    @task(5)
    def collections(self):
        self.client.get(
            "/collections", headers={"Authorization": f"Bearer {self.jwt_token}"}
        )

    def on_start(self):
        res = self.client.post(
            "/auth/token",
            auth=("admin", "admin"),
        )
        if res.status_code == 200:
            self.jwt_token = res.json()["access_token"]
        else:
            print("LOGIN FAILED", res.status_code, res.text)
