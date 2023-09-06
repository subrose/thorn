# Simulating a usecase of a simple ecommerce app
# Garden Inc is a flower ecommerce application that sells flowers online in the UK

# They have the following requirements
# A backend application for processing orders, the PII it stores consists of:
# - Customer details: name, email, phone
# - Credit card details

# Marketing team needs to phone number area codes to assess campaign effectiveness
# Marketing team needs access to plain email addresses to send marketing emails

# Customer service team needs to access to all customer details to process refunds

import os

from client import Actor, Policy
from faker import Faker
from faker_e164.providers import E164Provider
from wait import wait_for_api

VAULT_URL = os.environ.get("VAULT_URL", "http://localhost:3001")
wait_for_api(VAULT_URL)

admin = Actor(VAULT_URL, username="admin", password="admin")
# Create collection
admin.create_collection(
    schema={
        "name": "customers",
        "fields": {
            "name": {"type": "name", "indexed": False},
            "email": {"type": "email", "indexed": True},
            "phone": {"type": "phone_number", "indexed": False},
            "credit_card": {"type": "credit_card", "indexed": False},
            "address": {"type": "address", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

# Create policies
# Backend can write customer details
admin.create_policy(
    policy=Policy(
        policy_id="backend",
        effect="allow",
        actions=["write"],
        resources=["/collections/customers/*"],
    ),
    expected_statuses=[201, 409],
)

# Marketing can read masked records
admin.create_policy(
    policy=Policy(
        policy_id="marketing",
        effect="allow",
        actions=["read"],
        resources=[
            "/collections/customers/*/masked/*",
        ],
    ),
    expected_statuses=[201, 409],
)

# Customer service team can read all customer details in plain
admin.create_policy(
    policy=Policy(
        policy_id="customer-service",
        effect="allow",
        actions=["read"],
        resources=[
            "/collections/customers/*/plain/*",
        ],
    ),
    expected_statuses=[201, 409],
)

# Create actors
backend = Actor(VAULT_URL, username="backend", password="backend")
marketing = Actor(VAULT_URL, username="marketing", password="marketing")
customer_service = Actor(
    VAULT_URL, username="customer-service", password="customer-service"
)

admin.create_principal(
    username=backend.username,
    password=backend.password,
    description="backend",
    policies=["backend"],
    expected_statuses=[201, 409],
)

admin.create_principal(
    username=marketing.username,
    password=marketing.password,
    description="marketing",
    policies=["marketing"],
    expected_statuses=[201, 409],
)

admin.create_principal(
    username=customer_service.username,
    password=customer_service.password,
    description="customer-service",
    policies=["customer-service"],
    expected_statuses=[201, 409],
)

# Backend creates some customers
fake = Faker()
fake.add_provider(E164Provider)

# We need to create records one by one and build a map with the returned id:

records_map = {}
for i in range(10):
    record = {
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.e164(),
        "credit_card": fake.credit_card_full(),
        "address": fake.address(),
    }
    record_ids = backend.create_records(
        collection="customers", records=[record], expected_statuses=[201, 409]
    )
    records_map[record_ids[0]] = record

for record_id, record in records_map.items():
    # Backend can't read anything
    backend.get_record(
        collection="customers",
        record_id=record_id,
        return_formats="name.masked,email.masked,phone.masked",
        expected_statuses=[403],
    )

    backend.get_record(
        collection="customers",
        record_id=record_id,
        return_formats="name.plain,email.plain,phone.plain",
        expected_statuses=[403],
    )

    # Marketing can read masked records
    masked_record = marketing.get_record(
        collection="customers",
        record_id=record_id,
        return_formats="name.masked,email.masked,phone.masked",
        expected_statuses=[200],
    )
    # Check that masked record is masked correctly, first 5 digits are the same
    assert masked_record[record_id]["phone"][:5] == record["phone"][:5]
    # Check that masked record is masked correctly, rest of the digits are not the same
    assert masked_record[record_id]["phone"][5:] != record["phone"][5:]

    # Marketing can't read plain
    marketing.get_record(
        collection="customers",
        record_id=record_id,
        return_formats="name.plain,email.plain,phone.plain",
        expected_statuses=[403],
    )

    # Customer service can read plain
    plain_record = customer_service.get_record(
        collection="customers",
        record_id=record_id,
        return_formats="name.plain,email.plain,phone.plain",
        expected_statuses=[200],
    )

    # Check that plain record is the same as the original record
    assert plain_record[record_id]["name"] == record["name"]
    assert plain_record[record_id]["email"] == record["email"]
    assert plain_record[record_id]["phone"] == record["phone"]


print("ecommerce usecase completed successfully!")
