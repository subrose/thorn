# Simulating a usecase of a simple ecommerce app
# Garden Inc is a flower ecommerce application that sells flowers online in the UK

# They have the following requirements
# A backend application for processing orders, the PII it stores consists of:
# - Customer details: name, email, phone
# - Credit card details

# Marketing team needs to phone number area codes to assess campaign effectiveness
# Marketing team needs access to plain email addresses to send marketing emails

# Customer service team needs to access to all customer details to process refunds

from client import Actor
from client import Policy
from faker import Faker
from faker_e164.providers import E164Provider

VAULT_URL = "http://localhost:3001"
admin = Actor(VAULT_URL, username="admin", password="admin")
# Create collection
admin.create_collection(
    schema={
        "name": "customers",
        "fields": {
            "name": {"type": "name", "indexed": False},
            "email": {"type": "email", "indexed": True},
            "phone": {"type": "phone_number", "indexed": False},
            "credit-card": {"type": "credit-card", "indexed": False},
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
            "/collections/customers/*/masked",
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
            "/collections/customers/*/*/plain",
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
records = [
    {
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.e164(),
        "credit-card": fake.credit_card_full(),
        "address": fake.address(),
    }
    for _ in range(10)
]

record_ids = backend.create_records(
    collection="customers", records=records, expected_statuses=[201, 409]
)

# Backend can't read anything
backend.get_record(
    collection="customers",
    record_id=record_ids[0],
    format="masked",
    expected_statuses=[403],
)

backend.get_record(
    collection="customers",
    record_id=record_ids[0],
    format="plain",
    expected_statuses=[403],
)

# Marketing team can read plain email addresses and masked phone numbers
for i in range(len(record_ids)):
    record_id = record_ids[i]
    masked_record = marketing.get_record(
        collection="customers",
        record_id=record_id,
        format="masked",
        expected_statuses=[200],
    )
    # Check that masked record is masked correctly, first 5 digits are the same
    assert masked_record[record_id]["phone"][:5] == records[i]["phone"][:5]
    # Check that masked record is masked correctly, rest of the digits are not the same
    assert masked_record[record_id]["phone"][5:] != records[i]["phone"][5:]

# Marketing can't read plain
marketing.get_record(
    collection="customers",
    record_id=record_ids[0],
    format="plain",
    expected_statuses=[403],
)

# Customer service team can only read customer details in plain
customer_service.get_record(
    collection="customers",
    record_id=record_ids[0],
    format="plain",
    expected_statuses=[200],
)

customer_service.get_record(
    collection="customers",
    record_id=record_ids[0],
    format="masked",
    expected_statuses=[403],
)

# Problems:
# - Marketing team should not be able to read the whole record even if masked,
# We should be able to specify policies at the field level
