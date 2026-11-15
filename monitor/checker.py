import asyncio
import time
from dataclasses import dataclass

import httpx

from monitor.config import SiteConfig, load_config
from monitor.ssl_utils import SSLInspectionResult, inspect_ssl_certificate


@dataclass
class SiteResult:
    """Stores the result of a single website check."""

    name: str
    url: str
    is_up: bool
    status_code: int
    response_time_ms: float
    ssl_days_left: int | str
    error_msg: str = ""
    ssl_validation_error: str = ""
    ssl_metadata_error: str = ""


async def _probe_http(
    client: httpx.AsyncClient, site: SiteConfig
) -> tuple[httpx.Response | None, float, httpx.RequestError | None]:
    """Run the HTTP probe and retain its own response time and request error."""
    start_time = time.perf_counter()

    try:
        response = await client.head(site.url, follow_redirects=True)
    except httpx.RequestError as error:
        elapsed = (time.perf_counter() - start_time) * 1000
        return None, round(elapsed, 2), error

    elapsed = (time.perf_counter() - start_time) * 1000
    return response, round(elapsed, 2), None


async def check_uptime(client: httpx.AsyncClient, site: SiteConfig) -> SiteResult:
    """
    Check HTTP reachability and SSL inspection concurrently for one site.

    HTTP reachability, certificate metadata, and certificate trust validation
    are independent outcomes. An invalid certificate must remain visible even
    when the HTTP endpoint itself is reachable.
    """
    http_task = asyncio.create_task(_probe_http(client, site))
    ssl_task = asyncio.create_task(asyncio.to_thread(inspect_ssl_certificate, site.url))

    try:
        http_result, ssl_result = await asyncio.gather(
            http_task, ssl_task, return_exceptions=True
        )
    except asyncio.CancelledError:
        http_task.cancel()
        ssl_task.cancel()
        await asyncio.gather(http_task, ssl_task, return_exceptions=True)
        raise

    if isinstance(http_result, asyncio.CancelledError):
        raise http_result
    if isinstance(ssl_result, asyncio.CancelledError):
        raise ssl_result
    if isinstance(http_result, BaseException):
        raise http_result

    response, elapsed, request_error = http_result

    ssl_validation_error = ""
    ssl_metadata_error = ""
    if isinstance(ssl_result, SSLInspectionResult):
        ssl_days: int | str
        if ssl_result.days_left is None:
            ssl_days = (
                "Not HTTPS"
                if ssl_result.metadata_error == "Not HTTPS"
                else "Unavailable"
            )
        else:
            ssl_days = ssl_result.days_left
        ssl_validation_error = ssl_result.validation_error or ""
        ssl_metadata_error = ssl_result.metadata_error or ""
    elif isinstance(ssl_result, Exception):
        ssl_days = f"SSL check failed: {ssl_result}"
        ssl_metadata_error = str(ssl_result)
    elif isinstance(ssl_result, BaseException):
        raise ssl_result
    else:
        # Retain compatibility with simple integer/string check doubles.
        ssl_days = ssl_result

    if request_error is not None:
        return SiteResult(
            name=site.name,
            url=site.url,
            is_up=False,
            status_code=0,
            response_time_ms=elapsed,
            error_msg=str(request_error),
            ssl_days_left=ssl_days,
            ssl_validation_error=ssl_validation_error,
            ssl_metadata_error=ssl_metadata_error,
        )

    return SiteResult(
        name=site.name,
        url=site.url,
        is_up=response.status_code < 400,
        status_code=response.status_code,
        response_time_ms=elapsed,
        ssl_days_left=ssl_days,
        ssl_validation_error=ssl_validation_error,
        ssl_metadata_error=ssl_metadata_error,
    )


async def run_all_checks(
    sites: list[SiteConfig], timeout: int
) -> list[SiteResult]:
    """Check all configured sites concurrently using a shared HTTP client."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [check_uptime(client, site) for site in sites]
        return await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        app_config = load_config("../targets.yaml")
    except FileNotFoundError:
        app_config = load_config("targets.yaml")

    print(f"Starting concurrent checks for {len(app_config.sites)} sites...\n")

    start_total = time.perf_counter()
    results = asyncio.run(run_all_checks(app_config.sites, app_config.timeout))
    total_time = time.perf_counter() - start_total

    for res in results:
        status = "UP" if res.is_up else "DOWN"
        print(
            f"{status} | {res.status_code} | {res.response_time_ms}ms | {res.name} ({res.url})"
        )
        if res.error_msg:
            print(f"    Error: {res.error_msg}")
        if res.ssl_validation_error:
            print(f"    SSL validation failed: {res.ssl_validation_error}")
        if res.ssl_metadata_error:
            print(f"    SSL metadata unavailable: {res.ssl_metadata_error}")

    print(f"\nTotal execution time for all sites: {total_time:.2f} seconds")
