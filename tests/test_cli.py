from monitor.checker import SiteResult
from monitor.cli import init_config, print_table


def test_init_creates_file(tmp_path, monkeypatch):
    """sentinel init creates a targets.yaml with example content."""
    monkeypatch.chdir(tmp_path)

    init_config()

    config_file = tmp_path / "targets.yaml"
    assert config_file.exists()
    content = config_file.read_text()
    assert "sites:" in content
    assert "settings:" in content


def test_init_warns_if_exists(tmp_path, monkeypatch, capsys):
    """Sentinel init does not overwrite an existing targets.yaml."""
    monkeypatch.chdir(tmp_path)

    config_file = tmp_path / "targets.yaml"
    config_file.write_text("original content")

    init_config()

    captured = capsys.readouterr()
    assert "already exists" in captured.out
    assert config_file.read_text() == "original content"



def test_print_table_does_not_duplicate_tls_verification_error(capsys):
    """A TLS handshake failure is shown once, using the SSL inspection result."""
    result = SiteResult(
        name="ITS",
        url="https://its.example.com",
        is_up=False,
        status_code=0,
        response_time_ms=25.0,
        ssl_days_left=-5,
        error_msg=(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "self-signed certificate in certificate chain (_ssl.c:1032)"
        ),
        ssl_validation_error=(
            "self-signed certificate in certificate chain"
        ),
        is_reachable=False,
    )

    print_table([result])
    output = capsys.readouterr().out

    assert output.count("self-signed certificate in certificate chain") == 1
    assert "Error:" not in output
    assert "SSL validation failed:" in output
