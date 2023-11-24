# Simulating a usecase of PCI compliance with a payment gateway

import random

from client import Actor, Policy, init_client
from faker import Faker
from faker_e164.providers import E164Provider


vault_url = init_client()

admin = Actor(vault_url, username="admin", password="admin")
# Create collection
admin.create_collection(
    schema={
        "name": "credit_cards",
        "fields": {
            "name": {"type": "name", "indexed": False},
            "cc_number": {"type": "cc_number", "indexed": False},
            "cc_cvv": {"type": "cc_cvv", "indexed": False},
            "cc_expiry": {"type": "cc_expiry", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

# Create policies
# Backend can write customer details
admin.create_policy(
    policy=Policy(
        policy_id="backend-ccs",
        effect="allow",
        actions=["write"],
        resources=["/collections/credit_cards/*"],
    ),
    expected_statuses=[201, 409],
)

# CS can read masked records
admin.create_policy(
    policy=Policy(
        policy_id="cs-ccs",
        effect="allow",
        actions=["read"],
        resources=[
            "/collections/credit_cards/*/masked/*",
        ],
    ),
    expected_statuses=[201, 409],
)

# Proxy service can read plain for forwarding to payment gateway
admin.create_policy(
    policy=Policy(
        policy_id="proxy-ccs",
        effect="allow",
        actions=["read"],
        resources=[
            "/collections/credit_cards/*/plain/*",
        ],
    ),
    expected_statuses=[201, 409],
)

# Create actors
backend = Actor(vault_url, username="backend_cc", password="backend_cc")
cs = Actor(vault_url, username="cs_cc", password="cs_cc")
proxy = Actor(vault_url, username="proxy_cc", password="proxy_cc")

admin.create_principal(
    username=backend.username,
    password=backend.password,
    description="backend",
    policies=["backend-ccs"],
    expected_statuses=[201, 409],
)

admin.create_principal(
    username=cs.username,
    password=cs.password,
    description="cs",
    policies=["cs-ccs"],
    expected_statuses=[201, 409],
)

admin.create_principal(
    username=proxy.username,
    password=proxy.password,
    description="proxy",
    policies=["proxy-ccs"],
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
        "cc_number": fake.credit_card_number(
            card_type=random.choice(["visa", "mastercard", "amex"])
        ),
        "cc_cvv": fake.credit_card_security_code(),
        "cc_expiry": fake.credit_card_expire(),
    }
    record_ids = backend.create_records(
        collection="credit_cards", records=[record], expected_statuses=[201, 409]
    )
    records_map[record_ids[0]] = record

for record_id, record in records_map.items():
    # Backend can't read anything
    backend.get_record(
        collection="credit_cards",
        record_id=record_id,
        return_formats="name.masked,cc_number.masked,cc_cvv.masked,cc_expiry.masked",
        expected_statuses=[403],
    )

    # CS can read masked
    cs.get_record(
        collection="credit_cards",
        record_id=record_id,
        return_formats="name.masked,cc_number.masked,cc_cvv.masked,cc_expiry.masked",
        expected_statuses=[200],
    )

    # Proxy can read plain
    proxy.get_record(
        collection="credit_cards",
        record_id=record_id,
        return_formats="name.plain,cc_number.plain,cc_cvv.plain,cc_expiry.plain",
        expected_statuses=[200],
    )
