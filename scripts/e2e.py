"""Build-independent runner: install the supplied wheel outside the source tree.

Runs all three modes with real Uvicorn and a separate client process. --https
requires a Caddy executable and uses a freshly generated explicitly trusted CA.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2 as httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def certificates(folder):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "E2E local CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = folder / "test-ca.pem", folder / "test-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--https", action="store_true")
    parser.add_argument("--mcp", action="store_true")
    options = parser.parse_args()
    wheel = options.wheel.resolve(strict=True)
    root = Path(__file__).resolve().parents[1]
    caddy = shutil.which(os.environ.get("CADDY_BINARY", "caddy")) if options.https else None
    if options.https and not caddy:
        raise SystemExit("HTTPS E2E requires Caddy; set CADDY_BINARY to its executable")
    with tempfile.TemporaryDirectory(
        prefix="oauth21-e2e-", ignore_cleanup_errors=os.name == "nt"
    ) as temporary:
        folder = Path(temporary).resolve()
        if folder == root or root in folder.parents:
            raise SystemExit("E2E environment must be outside the checkout")
        for name in ("e2e_host.py", "e2e_client.py", "e2e_mcp.py", "e2e_mcp_client.py"):
            shutil.copyfile(root / "scripts" / name, folder / name)
        shutil.copyfile(root / "examples/fastapi_app.py", folder / "fastapi_app.py")
        subprocess.run([sys.executable, "-m", "venv", str(folder / "venv")], check=True)  # noqa: S603 -- fixed local interpreter, no shell
        python = folder / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        dependencies = [str(wheel) + "[example,cimd]", "httpx2>=2.13.1,<3"]
        if options.mcp:
            dependencies.append("mcp==2.3.0")
        subprocess.run(  # noqa: S603 -- fixed interpreter and dependencies
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-user",
                "--quiet",
                "--disable-pip-version-check",
                *dependencies,
            ],
            check=True,
        )
        ca, key = certificates(folder) if options.https else (None, None)
        for mode in ("dcr", "cimd", "cimd+dcr"):
            internal_port = port()
            external_port = port() if options.https else internal_port
            while options.https and external_port == internal_port:
                external_port = port()
            issuer = (
                f"https://localhost:{external_port}"
                if options.https
                else f"http://127.0.0.1:{external_port}"
            )
            env = {
                key: value
                for key, value in os.environ.items()
                if key not in ("PYTHONPATH", "E2E_CA", "E2E_INTERNAL", "E2E_MCP")
            }
            env.update(E2E_ISSUER=issuer, E2E_MODE=mode, PYTHONUNBUFFERED="1")
            if ca:
                env.update(E2E_CA=str(ca), E2E_INTERNAL=f"http://127.0.0.1:{internal_port}")
            if options.mcp:
                env["E2E_MCP"] = "1"
            with ExitStack() as stack:
                log = stack.enter_context(
                    (folder / f"server-{mode}.log").open("w", encoding="utf-8")
                )
                command = [
                    str(python),
                    "-m",
                    "uvicorn",
                    "e2e_host:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(internal_port),
                    "--no-access-log",
                    "--forwarded-allow-ips",
                    "127.0.0.1" if ca else "",
                ]
                server = subprocess.Popen(command, cwd=folder, env=env, stdout=log, stderr=log)  # noqa: S603 -- ephemeral test server, no shell
                stack.callback(stop, server)
                if ca:
                    config = folder / "Caddyfile"
                    config.write_text(
                        f'{{\n admin off\n auto_https off\n}}\nhttps://localhost:{external_port} {{\n bind 127.0.0.1\n tls "{ca.as_posix()}" "{key.as_posix()}"\n reverse_proxy 127.0.0.1:{internal_port}\n}}\n',
                        encoding="utf-8",
                    )
                    proxy = subprocess.Popen(  # noqa: S603 -- isolated proxy, no shell
                        [caddy, "run", "--config", str(config), "--adapter", "caddyfile"],
                        cwd=folder,
                        env=env,
                        stdout=log,
                        stderr=log,
                    )
                    stack.callback(stop, proxy)
                context = (
                    ssl.create_default_context(cafile=str(ca))
                    if ca
                    else ssl.create_default_context()
                )
                deadline = time.monotonic() + 30
                with httpx.Client(verify=context, trust_env=False, timeout=1) as probe:
                    while True:
                        try:
                            if (
                                probe.get(
                                    issuer + "/.well-known/oauth-authorization-server"
                                ).status_code
                                == 200
                            ):
                                break
                        except httpx.HTTPError:
                            pass
                        if server.poll() is not None or time.monotonic() > deadline:
                            log.flush()
                            raise RuntimeError(
                                (folder / f"server-{mode}.log").read_text(encoding="utf-8")
                            )
                        time.sleep(0.1)
                subprocess.run(  # noqa: S603 -- independent fixed client script
                    [str(python), str(folder / "e2e_client.py")],
                    cwd=folder,
                    env=env,
                    check=True,
                    timeout=90,
                )


if __name__ == "__main__":
    run()
