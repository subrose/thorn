import asyncio
import time

from aiohttp import BasicAuth, ClientSession
from client import Actor, init_client
from tabulate import tabulate
from statistics import stdev

N_RECORDS = 1000
CONCURRENCY_LIMIT = 10  # Set your desired concurrency limit


async def create_record_async(session, collection, record, semaphore):
    async with semaphore:
        start_time = time.time()
        async with session.post(
            f"{admin.vault_url}/collections/{collection}/records",
            json=record,
            auth=BasicAuth(admin.username, admin.password),
        ) as response:
            end_time = time.time()
            insert_times.append((end_time - start_time))
            return await response.json()


async def load_test_writes():
    async with ClientSession() as session:
        semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
        tasks = []
        for i in range(N_RECORDS):
            record = {
                "name": f"name{i}",
                "dob": f"dob{i}",
                "gender": f"gender{i}",
                "address": f"address{i}",
                "email": f"email{i}",
            }
            task = asyncio.ensure_future(
                create_record_async(session, "load", record, semaphore)
            )
            tasks.append(task)
        records.extend(await asyncio.gather(*tasks))


async def get_record_async(session, collection, record_id, semaphore):
    async with semaphore:
        start_time = time.time()
        async with session.get(
            f"{admin.vault_url}/collections/{collection}/records/{record_id}",
            params={
                "formats": "name.plain,dob.plain,gender.plain,address.plain,email.plain"
            },
            auth=BasicAuth(admin.username, admin.password),
        ) as response:
            end_time = time.time()
            read_times.append((end_time - start_time))
            return await response.json()


async def load_test_reads():
    async with ClientSession() as session:
        semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)
        tasks = []
        for record in records:
            task = asyncio.ensure_future(
                get_record_async(session, "load", record, semaphore)
            )
            tasks.append(task)
        await asyncio.gather(*tasks)


def calculate_stats(times):
    times_in_ms = [time * 1000 for time in times]
    return [
        round(min(times_in_ms), 2),
        round(sum(times_in_ms) / len(times_in_ms), 2),
        round(max(times_in_ms), 2),
        round(stdev(times_in_ms), 2),
        round(sorted(times_in_ms)[int(0.95 * len(times_in_ms))], 2),
        round(sorted(times_in_ms)[int(0.99 * len(times_in_ms))], 2),
    ]


if __name__ == "__main__":
    # Initialize client
    vault_url = init_client()
    admin = Actor(vault_url, username="admin", password="admin")

    admin.create_collection(
        schema={
            "name": "load",
            "fields": {
                "name": {
                    "type": "string",
                    "is_indexed": False,
                },
                "dob": {
                    "type": "string",
                    "is_indexed": False,
                },
                "gender": {
                    "type": "string",
                    "is_indexed": False,
                },
                "address": {
                    "type": "string",
                    "is_indexed": False,
                },
                "email": {
                    "type": "string",
                    "is_indexed": False,
                },
            },
        },
        expected_statuses=[201, 409],
    )

    # Load test inserting n records
    insert_times = []
    read_times = []
    records = []
    asyncio.run(load_test_writes())
    asyncio.run(load_test_reads())

    insert_stats = calculate_stats(insert_times)
    get_stats = calculate_stats(read_times)

    # Print stats in a table
    print(f"Results over {N_RECORDS} records:")
    print(
        tabulate(
            [insert_stats, get_stats],
            headers=[
                "Min (ms)",
                "Mean (ms)",
                "Max (ms)",
                "Std",
                "P95 (ms)",
                "P99 (ms)",
            ],
            tablefmt="pretty",
            showindex=["Write", "Read"],
        )
    )
