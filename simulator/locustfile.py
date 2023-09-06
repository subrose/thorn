import random

import requests
from faker import Faker
from faker_e164.providers import E164Provider
from locust import FastHttpUser, between, events, task


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    # Create a collection
    collection_json = {
        "name": "customers",
        "fields": {
            "name": {"type": "name", "indexed": False},
            "email": {"type": "email", "indexed": True},
            "phone": {"type": "phone_number", "indexed": True},
            "address": {"type": "address", "indexed": False},
        },
    }
    requests.post(
        f"{environment.host}/collections",
        json=collection_json,
        auth=("admin", "admin"),
    )
    print("INIT COMPLETE")


class AdminUser(FastHttpUser):
    wait_time = between(0.0001, 0.0001)
    records = []
    max_records = 1000
    fake = Faker()
    fake.add_provider(E164Provider)

    @task(2)
    def create_records(self):
        if len(self.records) >= self.max_records:
            return

        record_json = [
            {
                "name": self.fake.name(),
                "email": self.fake.email(),
                "phone": self.fake.e164(),
                "address": self.fake.address(),
            }
        ]

        res = self.client.post(
            "/collections/customers/records",
            json=record_json,
            auth=("admin", "admin"),
        )
        if res.status_code == 201:
            self.records.extend(res.json())
        else:
            print("CREATE RECORDS FAILED", res.status_code, res.text)

    @task(3)
    def get_records(self):
        if len(self.records) > 0:
            record_id = random.choice(self.records)
            res = self.client.get(
                f"/collections/customers/records/{record_id}",
                params={
                    "formats": (
                        "name.plain," "email.plain," "phone.plain," "address.plain"
                    )
                },
                auth=("admin", "admin"),
            )

            if res.status_code != 200:
                print("GET RECORD FAILED", res.status_code, res.text)

    @task(5)
    def collections(self):
        self.client.get(
            "/collections",
            auth=("admin", "admin"),
        )
