# Simulating a usecase of a simple ecommerce app
# Garden Inc is a flower ecommerce application that sells flowers online in the UK

# They have the following requirements
# A backend application for processing orders, the PII it stores consists of:
# - Customer details: name, email, phone
# - Credit card details

# Marketing team needs to phone number area codes to assess campaign effectiveness
# Marketing team needs access to plain email addresses to send marketing emails

# Customer service team needs to access to all customer details to process refunds


import random
from client import Actor, Policy, init_client
from faker import Faker
from faker_e164.providers import E164Provider

vault_url = init_client()

admin = Actor(vault_url, username="admin", password="admin")

admin.create_collection(
    schema={
        "name": "cards",
        "fields": {
            "credit_card": {"type": "credit_card", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

admin.create_collection(
    schema={
        "name": "profiles",
        "fields": {
            "name": {"type": "name", "indexed": False},
            "email": {"type": "email", "indexed": True},
            "phone": {"type": "phone_number", "indexed": False},
            "address": {"type": "address", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

# Create policies
# Backend can write customer details
backend_policy = admin.create_policy(
    policy=Policy(
        effect="allow",
        actions=["write", "read"],
        resources=[
            "/collections/cards/records",
            "/collections/profiles/records",
            "/collections/cards/records/*/*.plain",
            "/collections/profile/records/*/*.plain",
            "/subjects",
            "/subjects/*",
        ],
    ),
    expected_statuses=[201, 409],
)

backend = Actor(vault_url, username="backend", password="backend")

admin.create_principal(
    username=backend.username,
    password=backend.password,
    description="backend",
    policies=[backend_policy["id"]],
    expected_statuses=[201, 409],
)


fake = Faker()
fake.add_provider(E164Provider)

# We need to create records one by one and build a map with the returned id:
records_map = {}  # key: subject id, value: record id
for i in range(3):
    customer = {
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.e164(),
        "address": fake.address(),
        "credit_card": fake.credit_card_full(),
    }
    # Create a subject
    sub = backend.create_subject(
        eid=customer["email"],
    )
    # Create a record
    record_id = backend.create_record(
        collection="cards",
        record={"credit_card": customer["credit_card"], "sid": sub["id"]},
        expected_statuses=[201, 409],
    )

    # create a profile
    profile_id = backend.create_record(
        collection="profiles",
        record={
            "name": customer["name"],
            "email": customer["email"],
            "phone": customer["phone"],
            "address": customer["address"],
            "sid": sub["id"],
        },
        expected_statuses=[201, 409],
    )

    records_map[sub["id"]] = {
        "record_id": record_id,
    }

# Delete a subject
random_subject_id = random.choice(list(records_map.keys()))
backend.delete_subject(
    sid=random_subject_id,
    expected_statuses=[204],
)

# Check if associated records are deleted
backend.get_record(
    collection="cards",
    record_id=records_map[random_subject_id]["record_id"],
    return_formats="credit_card.plain",
    expected_statuses=[404],
)

backend.get_record(
    collection="profile",
    record_id=records_map[random_subject_id]["record_id"],
    return_formats="name.plain,email.plain,phone.plain,address.plain",
    expected_statuses=[404],
)
