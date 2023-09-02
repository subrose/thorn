# Simulating a usecase where employees of a company are only allowed to access PII
# if they are in the same country as the customer


from client import Actor
from faker import Faker
from faker_e164.providers import E164Provider
from wait import wait_for_api
import os

VAULT_URL = os.environ.get("VAULT_URL", "http://localhost:3001")
wait_for_api(VAULT_URL)

admin = Actor(VAULT_URL, username="admin", password="admin")

# Create collection
admin.create_collection(
    schema={
        "name": "users",
        "fields": {
            "name": {"type": "name", "indexed": False},
            "email": {"type": "email", "indexed": True},
            "phone": {"type": "phone_number", "indexed": False},
            "country": {"type": "country", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

faker = Faker()
faker.add_provider(E164Provider)

# Create records
for _ in range(100):
    user = {
        "name": faker.name(),
        "email": faker.email(),
        "phone": faker.phone_number(),
        "country": faker.country(),
    }
    admin.create_record("users", user)


# How do we model policies for this usecase?
# We need policy enforcement to be dynamic based on the user's country
# For example:
# Policy(
#     policy_id="customer-service",
#     effect="allow",
#     actions=["read"],
#     resources=[
#         "/collections/users/*/plain/*",
#         "/collections/users/*/masked/*",
#     ],
#     conditions=[
#         Condition(
#             accessor_attribute="country",
#             operator="eq",
#             resource_field="country")
#     ],
# )
