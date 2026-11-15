import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

from cryptography import x509


@dataclass(frozen=True)
class SSLInspectionResult:
    """Keep certificate metadata and trust validation as separate outcomes."""

    days_left: int | None
    metadata_error: str | None = None
    validation_error: str | None = None

    @property
    def is_valid(self) -> bool:
        """Return true only when metadata was read and TLS validation succeeded."""
        return (
            self.days_left is not None
            and self.metadata_error is None
            and self.validation_error is None
        )


def _connect_and_get_certificate(
    hostname: str, port: int, timeout: int
) -> bytes:
    """Retrieve the peer certificate without treating it as trusted."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with (
        socket.create_connection((hostname, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=hostname) as tls_socket,
    ):
        certificate = tls_socket.getpeercert(binary_form=True)

    if not certificate:
        raise ssl.SSLError("The server did not provide a peer certificate")

    return certificate


def _validate_certificate(
    hostname: str, port: int, timeout: int, cafile: str | None
) -> None:
    """Perform a normal TLS handshake with chain and hostname verification."""
    context = ssl.create_default_context(cafile=cafile)

    with (
        socket.create_connection((hostname, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=hostname),
    ):
        pass


def _describe_error(error: Exception) -> str:
    if isinstance(error, socket.gaierror):
        return f"DNS lookup failed: {error}"
    if isinstance(error, TimeoutError):
        return f"Connection timed out: {error}"
    return str(error)


def inspect_ssl_certificate(
    url: str, timeout: int = 5, cafile: str | None = None
) -> SSLInspectionResult:
    """
    Inspect certificate expiry independently from TLS trust validation.

    The first connection retrieves the peer certificate without verification so
    expired or untrusted certificates can still be inspected. A second
    connection uses the normal trust store and hostname verification. Metadata
    retrieval alone is never treated as proof that a certificate is valid.
    """
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            return SSLInspectionResult(
                days_left=None,
                metadata_error="Not HTTPS",
            )

        hostname = parsed_url.hostname
        if not hostname:
            return SSLInspectionResult(
                days_left=None,
                metadata_error="Invalid HTTPS URL",
            )

        parsed_port = parsed_url.port
        port = 443 if parsed_port is None else parsed_port
        certificate_der = _connect_and_get_certificate(hostname, port, timeout)
        certificate = x509.load_der_x509_certificate(certificate_der)
        days_left = (certificate.not_valid_after_utc - datetime.now(UTC)).days

    except (OSError, ssl.SSLError, ValueError) as error:
        return SSLInspectionResult(
            days_left=None,
            metadata_error=f"Certificate metadata unavailable: {_describe_error(error)}",
        )

    try:
        _validate_certificate(hostname, port, timeout, cafile)
    except (OSError, ssl.SSLError, ValueError) as error:
        return SSLInspectionResult(
            days_left=days_left,
            validation_error=f"Certificate validation failed: {_describe_error(error)}",
        )

    return SSLInspectionResult(days_left=days_left)


# Backwards-compatible name for callers that only need the expiry value.
def get_ssl_expiry_days(url: str, timeout: int = 5) -> int | str:
    result = inspect_ssl_certificate(url, timeout=timeout)
    if result.days_left is None:
        return result.metadata_error or "Certificate metadata unavailable"
    if result.validation_error:
        return result.validation_error
    return result.days_left


if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "http://neverssl.com",
        "https://this-does-not-exist.org",
    ]

    for test_url in test_urls:
        result = inspect_ssl_certificate(test_url)
        print(
            f"[{test_url}] expiry={result.days_left}, "
            f"valid={result.is_valid}, "
            f"metadata_error={result.metadata_error}, "
            f"validation_error={result.validation_error}"
        )
