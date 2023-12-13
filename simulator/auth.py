from client import Actor, init_client
from faker import Faker
from faker_e164.providers import E164Provider

vault_url = init_client()

admin = Actor(vault_url, username="admin", password="admin")
# Create collection
admin.create_collection(
    schema={
        "name": "users",
        "fields": {
            "email": {"type": "email", "indexed": True},
            "password": {"type": "phone_number", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)


# admin creates some customers
fake = Faker()
fake.add_provider(E164Provider)

# We need to create records one by one and build a map with the returned id:

records_map = {}
email_map = {}
for i in range(10):
    record = {
        "email": fake.email(),
        "password": fake.e164(),
    }
    record_id = admin.create_record(
        collection="users", record=record, expected_statuses=[201, 409]
    )
    records_map[record_id] = record
    email_map[record["email"]] = record

# Can retrieve record by email and password
for email, record_id in email_map.items():
    record = admin.search_records(
        collection="users",
        filters={"email": email, "password": record_id["password"]},
        expected_statuses=[200],
    )

# Ensure that policies work for record access
