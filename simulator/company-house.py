# Simulating the UK company house usecase where we need to register:
# - Company details: name, address, phone, email
# - Company directors: name, address, phone, email, company
# Access control is out of scope for this usecase, just experimenting with Subjects
# If a company is deleted, all associated records should be deleted as well

from client import Actor, init_client
from faker import Faker
from faker_e164.providers import E164Provider

vault_url = init_client()

admin = Actor(vault_url, username="admin", password="admin")

admin.create_collection(
    schema={
        "name": "companies",
        "fields": {
            "registration_number": {"type": "string", "indexed": True},
            "name": {"type": "name", "indexed": False},
            "email": {"type": "email", "indexed": True},
            "phone": {"type": "phone_number", "indexed": False},
            "address": {"type": "address", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)

admin.create_collection(
    schema={
        "name": "directors",
        "fields": {
            "name": {"type": "name", "indexed": False},
            "email": {"type": "email", "indexed": True},
            "phone": {"type": "phone_number", "indexed": False},
            "address": {"type": "address", "indexed": False},
            "shares": {"type": "integer", "indexed": False},
            "company": {"type": "string", "indexed": False},
        },
    },
    expected_statuses=[201, 409],
)


fake = Faker()
fake.add_provider(E164Provider)

# We need to create records one by one and build a map with the returned id:
company_records_map = {}

for i in range(3):
    company = {
        "registration_number": "company_" + fake.ean(length=13),
        "name": fake.name(),
        "email": fake.email(),
        "phone": fake.e164(),
        "address": fake.address(),
    }
    # Create a subject
    sub = admin.create_subject(
        eid=company["registration_number"],
    )

    # Create company record
    admin.create_record(
        collection="companies",
        record={**company, "sid": sub["id"]},
        expected_statuses=[201, 409],
    )

    # Create company director records
    for j in range(3):
        director = {
            "name": fake.name(),
            "email": fake.email(),
            "phone": fake.e164(),
            "address": fake.address(),
            "shares": str(fake.random_int(min=1, max=100)),  # a hack, until: SUB-32
            "company": company["registration_number"],
        }
        sub = admin.create_subject(
            eid="email_" + director["email"],
        )
        admin.create_record(
            collection="directors",
            record={**director, "sid": sub["id"]},
            expected_statuses=[201, 409],
        )

# ??? How to delete a company and all associated records?
# Does mixing subjects in one table make sense?
