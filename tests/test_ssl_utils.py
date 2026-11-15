import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from monitor.ssl_utils import inspect_ssl_certificate


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


@pytest.fixture(scope="module")
def trusted_ca(tmp_path_factory):
    directory = tmp_path_factory.mktemp("tls-ca")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sentinel Test CA")])
    now = datetime.now(UTC).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca_path = directory / "ca.pem"
    ca_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key, certificate, ca_path


def _create_server_certificate(
    directory: Path,
    *,
    issuer_key,
    issuer_certificate,
    dns_name: str,
    not_before: datetime,
    not_after: datetime,
    self_signed: bool = False,
):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_name)])
    issuer = subject if self_signed else issuer_certificate.subject
    signing_key = key if self_signed else issuer_key
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before.replace(tzinfo=None))
        .not_valid_after(not_after.replace(tzinfo=None))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(signing_key, hashes.SHA256())
    )

    cert_path = directory / "server.pem"
    key_path = directory / "server-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    _write_private_key(key_path, key)
    return cert_path, key_path


class _LocalTLSServer:
    def __init__(self, cert_path: Path, key_path: Path):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop_event = threading.Event()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        def serve():
            while not self.stop_event.is_set():
                try:
                    connection, _ = self.listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break

                try:
                    with context.wrap_socket(connection, server_side=True):
                        pass
                except (OSError, ssl.SSLError):
                    connection.close()

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=2)


@pytest.fixture
def tls_server_factory(tmp_path, trusted_ca):
    ca_key, ca_certificate, _ = trusted_ca
    servers = []

    def start(
        *,
        dns_name="localhost",
        not_before=None,
        not_after=None,
        self_signed=False,
    ):
        now = datetime.now(UTC)
        cert_path, key_path = _create_server_certificate(
            tmp_path,
            issuer_key=ca_key,
            issuer_certificate=ca_certificate,
            dns_name=dns_name,
            not_before=not_before or now - timedelta(days=1),
            not_after=not_after or now + timedelta(days=30),
            self_signed=self_signed,
        )
        server = _LocalTLSServer(cert_path, key_path)
        servers.append(server)
        return server

    yield start

    for server in servers:
        server.close()


def test_non_https_url_does_not_attempt_tls_connection():
    result = inspect_ssl_certificate("http://localhost")

    assert result.days_left is None
    assert result.metadata_error == "Not HTTPS"
    assert result.is_valid is False


def test_valid_certificate_has_metadata_and_passes_validation(
    tls_server_factory, trusted_ca
):
    _, _, ca_path = trusted_ca
    server = tls_server_factory()

    result = inspect_ssl_certificate(
        f"https://localhost:{server.port}", cafile=str(ca_path)
    )

    assert result.days_left is not None
    assert 28 <= result.days_left <= 30
    assert result.metadata_error is None
    assert result.validation_error is None
    assert result.is_valid is True


def test_expired_certificate_metadata_is_available_but_invalid(
    tls_server_factory, trusted_ca
):
    _, _, ca_path = trusted_ca
    now = datetime.now(UTC)
    server = tls_server_factory(
        not_before=now - timedelta(days=10),
        not_after=now - timedelta(days=2),
    )

    result = inspect_ssl_certificate(
        f"https://localhost:{server.port}", cafile=str(ca_path)
    )

    assert result.days_left is not None
    assert result.days_left < 0
    assert result.metadata_error is None
    assert result.validation_error is not None
    assert "expired" in result.validation_error.lower()
    assert result.is_valid is False


def test_untrusted_certificate_metadata_is_available_but_invalid(
    tls_server_factory,
):
    server = tls_server_factory(self_signed=True)

    result = inspect_ssl_certificate(f"https://localhost:{server.port}")

    assert result.days_left is not None
    assert result.metadata_error is None
    assert result.validation_error is not None
    assert "certificate" in result.validation_error.lower()
    assert result.is_valid is False


def test_hostname_mismatch_is_a_validation_failure(
    tls_server_factory, trusted_ca
):
    _, _, ca_path = trusted_ca
    server = tls_server_factory(dns_name="wrong.example")

    result = inspect_ssl_certificate(
        f"https://localhost:{server.port}", cafile=str(ca_path)
    )

    assert result.days_left is not None
    assert result.metadata_error is None
    assert result.validation_error is not None
    assert "hostname" in result.validation_error.lower()
    assert result.is_valid is False


def test_connection_failure_is_reported_as_missing_metadata():
    reservation = socket.socket()
    reservation.bind(("127.0.0.1", 0))
    port = reservation.getsockname()[1]
    reservation.close()

    result = inspect_ssl_certificate(f"https://127.0.0.1:{port}", timeout=1)

    assert result.days_left is None
    assert result.metadata_error is not None
    assert "metadata unavailable" in result.metadata_error.lower()
    assert result.is_valid is False
