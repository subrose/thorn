# Use tenacity to wait for the api to be ready

import tenacity
import requests
import logging
import sys

logger = logging.getLogger(__name__)

# Format the log messages nicely
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


@tenacity.retry(
    wait=tenacity.wait_fixed(1),
    stop=tenacity.stop_after_attempt(60),
    before_sleep=tenacity.before_sleep_log(logger, logging.DEBUG),
    retry=tenacity.retry_if_exception_type(tenacity.TryAgain),
)
def wait_for_api(vault_url: str) -> None:
    try:
        response = requests.get(f"{vault_url}/health")
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        logger.info("Waiting for api to be ready ...")
        raise tenacity.TryAgain
    except requests.exceptions.HTTPError as e:
        logger.error("API is up but not ready")
        logger.error(e, exc_info=True, stack_info=True)
        sys.exit(1)


if __name__ == "__main__":
    wait_for_api("http://localhost:8200")
