import glob
import json
import os
import random
import shutil
import subprocess
import socket
import tempfile
import time

import pytest
import pkcs11
from pkcs11 import KeyType

from test_pkcs11_proxy import (
    get_pkcs11_library_path,
    _get_free_port,
    _load_proxy_lib,
    _terminate_daemon,
    get_softhsm2_conf,
)


def _run_cmd(cmd, env=None):
    return subprocess.run(cmd, env=env, capture_output=True, text=True)


def _openssl_available():
    return shutil.which("openssl") is not None


def _pkcs11_tool_available():
    return shutil.which("pkcs11-tool") is not None


def _find_pkcs11_provider_module():
    for env_name in ("PKCS11_PROVIDER_MODULE", "PKCS11_PROVIDER_MODULE_PATH"):
        path = os.getenv(env_name)
        if path and os.path.exists(path):
            return path
    candidates = [
        "/usr/lib/ossl-modules/pkcs11.so",
        "/usr/lib64/ossl-modules/pkcs11.so",
        "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",
        "/usr/local/lib/ossl-modules/pkcs11.so",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    nix_candidates = glob.glob("/nix/store/*-pkcs11-provider-*/lib/ossl-modules/pkcs11.so")
    for path in nix_candidates:
        if os.path.exists(path):
            return path
    return None


def _openssl_fingerprint_sha256(cert_path):
    result = _run_cmd(["openssl", "x509", "-in", cert_path, "-noout", "-fingerprint", "-sha256"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    line = result.stdout.strip()
    if "=" in line:
        line = line.split("=", 1)[1]
    return line.replace(":", "").lower()


def _get_free_port_safe():
    env = os.getenv("PKCS11_TEST_PORT")
    if env:
        return int(env)
    try:
        return _get_free_port()
    except PermissionError:
        return random.randint(20000, 40000)


def _generate_mtls_materials_openssl(server_san_ip="127.0.0.1", client_names=("clientA", "clientB")):
    if not _openssl_available():
        pytest.skip("openssl not available")
    temp_dir = tempfile.mkdtemp(prefix="pkcs11-proxy-authz-")
    ca_key = os.path.join(temp_dir, "ca.key")
    ca_crt = os.path.join(temp_dir, "ca.crt")
    server_key = os.path.join(temp_dir, "server.key")
    server_csr = os.path.join(temp_dir, "server.csr")
    server_crt = os.path.join(temp_dir, "server.crt")
    server_ext = os.path.join(temp_dir, "server_ext.cnf")

    with open(server_ext, "w") as f:
        f.write(f"subjectAltName=IP:{server_san_ip}\n")

    subprocess.run(["openssl", "genrsa", "-out", ca_key, "2048"], check=True)
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-key", ca_key,
        "-subj", "/CN=pkcs11-proxy-test-ca", "-days", "30", "-out", ca_crt,
        "-addext", "basicConstraints=CA:TRUE",
        "-addext", "keyUsage=keyCertSign,cRLSign",
    ], check=True)

    subprocess.run(["openssl", "genrsa", "-out", server_key, "2048"], check=True)
    subprocess.run([
        "openssl", "req", "-new", "-key", server_key,
        "-subj", "/CN=pkcs11-proxy-server", "-out", server_csr,
        "-addext", "basicConstraints=CA:FALSE",
        "-addext", "extendedKeyUsage=serverAuth",
    ], check=True)
    subprocess.run([
        "openssl", "x509", "-req", "-in", server_csr,
        "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
        "-days", "30", "-out", server_crt, "-extfile", server_ext
    ], check=True)

    clients = {}
    for name in client_names:
        key_path = os.path.join(temp_dir, f"{name}.key")
        csr_path = os.path.join(temp_dir, f"{name}.csr")
        crt_path = os.path.join(temp_dir, f"{name}.crt")
        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
        subprocess.run([
            "openssl", "req", "-new", "-key", key_path,
            "-subj", f"/CN={name}", "-out", csr_path,
            "-addext", "basicConstraints=CA:FALSE",
            "-addext", "extendedKeyUsage=clientAuth",
        ], check=True)
        subprocess.run([
            "openssl", "x509", "-req", "-in", csr_path,
            "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
            "-days", "30", "-out", crt_path
        ], check=True)
        clients[name] = {"cert": crt_path, "key": key_path}

    return {
        "temp_dir": temp_dir,
        "ca_cert": ca_crt,
        "server_cert": server_crt,
        "server_key": server_key,
        "clients": clients,
    }


def _generate_self_signed_client_cert(temp_dir, name):
    key_path = os.path.join(temp_dir, f"{name}.key")
    crt_path = os.path.join(temp_dir, f"{name}.crt")
    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-key", key_path,
        "-subj", f"/CN={name}", "-days", "30", "-out", crt_path,
    ], check=True)
    return {"cert": crt_path, "key": key_path}


def _generate_client_cert_with_ca(temp_dir, ca_key, ca_crt, name):
    key_path = os.path.join(temp_dir, f"{name}.key")
    csr_path = os.path.join(temp_dir, f"{name}.csr")
    crt_path = os.path.join(temp_dir, f"{name}.crt")
    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
    subprocess.run([
        "openssl", "req", "-new", "-key", key_path,
        "-subj", f"/CN={name}", "-out", csr_path,
        "-addext", "basicConstraints=CA:FALSE",
        "-addext", "extendedKeyUsage=clientAuth",
    ], check=True)
    subprocess.run([
        "openssl", "x509", "-req", "-in", csr_path,
        "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
        "-days", "30", "-out", crt_path
    ], check=True)
    return {"cert": crt_path, "key": key_path}


def _write_openssl_pkcs11_conf(conf_path, provider_module, pkcs11_module):
    with open(conf_path, "w") as f:
        f.write(
            "openssl_conf = openssl_init\n\n"
            "[openssl_init]\n"
            "providers = provider_sect\n\n"
            "[provider_sect]\n"
            "default = default_sect\n"
            "pkcs11 = pkcs11_sect\n\n"
            "[default_sect]\n"
            "activate = 1\n\n"
            "[pkcs11_sect]\n"
            f"module = {provider_module}\n"
            f"pkcs11-module = {pkcs11_module}\n"
            f"pkcs11-module-path = {pkcs11_module}\n"
            "pkcs11-module-token-pin = 1234\n"
            "activate = 1\n"
        )


def _start_daemon_with_logs(pkcs11_lib, env, log_path):
    build_dir = os.path.join(os.path.dirname(__file__), "../build")
    pkcs11_daemon_path = os.path.join(build_dir, "pkcs11-daemon")
    if not os.path.exists(pkcs11_daemon_path):
        pytest.skip("pkcs11-daemon not built")
    log_file = open(log_path, "w")
    proc = subprocess.Popen([pkcs11_daemon_path, pkcs11_lib], env=env, stdout=log_file, stderr=log_file)
    return proc, log_file


def _wait_for_port(host, port, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                sock.connect((host, port))
                return True
        except Exception:
            time.sleep(0.1)
    return False


def _wait_for_daemon(daemon_process, log_path, proxy_socket):
    try:
        port = int(proxy_socket.rsplit(":", 1)[1])
    except Exception:
        port = None
    if port is not None and _wait_for_port("127.0.0.1", port):
        return
    if daemon_process.poll() is not None:
        with open(log_path, "r") as lf:
            logs = lf.read()
        pytest.fail(f"pkcs11-daemon exited early. Logs:\\n{logs}")
    pytest.fail("pkcs11-daemon did not become ready in time")


def _ensure_softhsm_conf():
    path = get_softhsm2_conf()
    if not os.path.exists(path):
        pytest.skip("softhsm2.conf not found")
    return path


def _authz_base_functions():
    return [
        "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetSlotList", "C_GetSlotInfo",
        "C_GetTokenInfo", "C_GetMechanismList", "C_GetMechanismInfo", "C_GetSessionInfo",
        "C_GenerateRandom", "C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_Login", "C_Logout",
        "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetAttributeValue",
        "C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal",
    ]


def test_mtls_authz_allows_sign():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")
    clientA = mtls["clients"]["clientA"]
    fingerprint = _openssl_fingerprint_sha256(clientA["cert"])

    policy = {
        "version": 1,
        "default": "deny",
        "clients": [
            {
                "id_type": "cert_fingerprint_sha256",
                "id": fingerprint,
                "allow": {
                    "pkcs11_functions": _authz_base_functions(),
                    "tokens": ["ProxyTestToken"],
                    "objects": ["ProxyTestExistingECKey"],
                },
            }
        ],
    }
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "enforce",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
        "PKCS11_PROXY_AUTHZ_LOG_LEVEL": "debug",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        client_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientA["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientA["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        proxy_lib = _load_proxy_lib()
        data_path = os.path.join(mtls["temp_dir"], "data.txt")
        sig_path = os.path.join(mtls["temp_dir"], "sig.bin")
        with open(data_path, "w") as f:
            f.write("hello")
        result = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "--login", "--pin", "1234",
            "--sign", "--mechanism", "ECDSA", "--id", "01",
            "--input-file", data_path, "--output-file", sig_path,
        ], env=client_env)
        assert result.returncode == 0, result.stderr
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_mtls_authz_denies_sign():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")
    clientA = mtls["clients"]["clientA"]
    clientB = mtls["clients"]["clientB"]

    fingerprint = _openssl_fingerprint_sha256(clientA["cert"])
    policy = {
        "version": 1,
        "default": "deny",
        "clients": [
            {
                "id_type": "cert_fingerprint_sha256",
                "id": fingerprint,
                "allow": {
                    "pkcs11_functions": _authz_base_functions(),
                    "tokens": ["ProxyTestToken"],
                    "objects": ["ProxyTestExistingECKey"],
                },
            }
        ],
    }
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "enforce",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
        "PKCS11_PROXY_AUTHZ_LOG_LEVEL": "debug",
        "PKCS11_PROXY_AUTHZ_LOG_LEVEL": "debug",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        client_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientB["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientB["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        proxy_lib = _load_proxy_lib()
        data_path = os.path.join(mtls["temp_dir"], "data.txt")
        sig_path = os.path.join(mtls["temp_dir"], "sig.bin")
        with open(data_path, "w") as f:
            f.write("hello")
        result = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "--login", "--pin", "1234",
            "--sign", "--mechanism", "ECDSA", "--id", "01",
            "--input-file", data_path, "--output-file", sig_path,
        ], env=client_env)
        assert result.returncode != 0

        log_file.flush()
        with open(log_path, "r") as lf:
            logs = lf.read()
        if logs:
            assert "AUTHZ DENY" in logs
        assert "fingerprint=" in logs
        assert "function=" in logs
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_mtls_authz_allows_enumeration_but_denies_keygen():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")
    clientA = mtls["clients"]["clientA"]
    fingerprint = _openssl_fingerprint_sha256(clientA["cert"])

    allow_list = [
        "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetSlotList", "C_GetSlotInfo",
        "C_GetTokenInfo", "C_GetMechanismList", "C_GetMechanismInfo", "C_GetSessionInfo",
        "C_OpenSession", "C_CloseSession", "C_Login", "C_Logout",
        "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal",
    ]
    policy = {
        "version": 1,
        "default": "deny",
        "clients": [
            {
                "id_type": "subject_cn",
                "id": "clientA",
                "allow": {
                    "pkcs11_functions": allow_list,
                    "tokens": ["ProxyTestToken"],
                },
            },
            {
                "id_type": "cert_fingerprint_sha256",
                "id": fingerprint,
                "allow": {
                    "pkcs11_functions": allow_list,
                    "tokens": ["ProxyTestToken"],
                },
            }
        ],
    }
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "audit",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
        "PKCS11_PROXY_AUTHZ_LOG_LEVEL": "debug",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        proxy_lib = _load_proxy_lib()
        client_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientA["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientA["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        old_env = os.environ.copy()
        os.environ.update(client_env)
        try:
            lib = pkcs11.lib(proxy_lib)
            token = lib.get_token(token_label="ProxyTestToken")
            with token.open(user_pin="1234", rw=True) as session:
                _ = list(token.slot.get_mechanisms())
                public_key, private_key = session.generate_keypair(
                    KeyType.RSA, 2048, store=False, label="AuthzDeniedKey"
                )
                assert public_key is not None
                assert private_key is not None
            log_file.flush()
            with open(log_path, "r") as lf:
                logs = lf.read()
            assert "AUTHZ AUDIT" in logs
        except pkcs11.PKCS11Error:
            log_file.flush()
            with open(log_path, "r") as lf:
                logs = lf.read()
            pytest.fail(f"pkcs11 enumeration failed. Logs:\n{logs}")
        finally:
            os.environ.clear()
            os.environ.update(old_env)
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_authz_default_deny_no_match():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")
    clientB = mtls["clients"]["clientB"]

    policy = {"version": 1, "default": "deny", "clients": []}
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "enforce",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        proxy_lib = _load_proxy_lib()
        client_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientB["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientB["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        result = _run_cmd(["pkcs11-tool", "--module", proxy_lib, "-L"], env=client_env)
        assert result.returncode != 0
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_authz_audit_mode_logs_only():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")
    clientB = mtls["clients"]["clientB"]

    policy = {
        "version": 1,
        "default": "deny",
        "clients": [
            {
                "id_type": "subject_cn",
                "id": "clientB",
                "allow": {
                    "pkcs11_functions": ["C_Initialize", "C_Finalize"],
                },
            }
        ],
    }
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "audit",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        client_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientB["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientB["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        proxy_lib = _load_proxy_lib()
        data_path = os.path.join(mtls["temp_dir"], "data.txt")
        sig_path = os.path.join(mtls["temp_dir"], "sig.bin")
        with open(data_path, "w") as f:
            f.write("hello")
        result = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "--login", "--pin", "1234",
            "--sign", "--mechanism", "ECDSA", "--id", "01",
            "--input-file", data_path, "--output-file", sig_path,
        ], env=client_env)
        assert result.returncode == 0, result.stderr

        log_file.flush()
        with open(log_path, "r") as lf:
            logs = lf.read()
        if logs:
            assert "AUTHZ AUDIT" in logs
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_authz_requires_peer_cert_when_enforced():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")
    clientA = mtls["clients"]["clientA"]

    policy = {"version": 1, "default": "deny", "clients": []}
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "false",
        "PKCS11_PROXY_AUTHZ_MODE": "enforce",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        proxy_lib = _load_proxy_lib()
        client_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientA["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientA["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        result = _run_cmd(["pkcs11-tool", "--module", proxy_lib, "-L"], env=client_env)
        assert result.returncode != 0
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_authz_object_label_scoping_denies_other_key():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")
    clientA = mtls["clients"]["clientA"]
    fingerprint = _openssl_fingerprint_sha256(clientA["cert"])

    allow_list = _authz_base_functions() + ["C_GenerateKeyPair"]
    policy = {
        "version": 1,
        "default": "deny",
        "clients": [
            {
                "id_type": "cert_fingerprint_sha256",
                "id": fingerprint,
                "allow": {
                    "pkcs11_functions": allow_list,
                    "tokens": ["ProxyTestToken"],
                    "objects": ["ProxyTestExistingECKey"],
                },
            }
        ],
    }
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "enforce",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        proxy_lib = _load_proxy_lib()
        client_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientA["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientA["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }

        keygen = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "--login", "--pin", "1234",
            "--keypairgen", "--key-type", "EC:prime256v1", "--label", "DeniedKey", "--id", "02",
        ], env=client_env)
        assert keygen.returncode != 0, keygen.stderr

        data_path = os.path.join(mtls["temp_dir"], "data.bin")
        sig_path = os.path.join(mtls["temp_dir"], "sig.bin")
        with open(data_path, "wb") as f:
            f.write(b"denied-sign-test")

        sign = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "--login", "--pin", "1234",
            "--sign", "--mechanism", "ECDSA", "--id", "02",
            "--input-file", data_path, "--output-file", sig_path,
        ], env=client_env)
        assert sign.returncode != 0, sign.stderr

        log_file.flush()
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_authz_two_clients_different_permissions():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")

    clientA = mtls["clients"]["clientA"]
    clientB = mtls["clients"]["clientB"]
    fp_a = _openssl_fingerprint_sha256(clientA["cert"])
    fp_b = _openssl_fingerprint_sha256(clientB["cert"])

    allow_a = [fn for fn in _authz_base_functions() if not fn.startswith("C_Sign")]
    allow_b = [fn for fn in _authz_base_functions() if not fn.startswith("C_Sign")] + ["C_GenerateKeyPair"]

    policy = {
        "version": 1,
        "default": "deny",
        "clients": [
            {
                "id_type": "cert_fingerprint_sha256",
                "id": fp_a,
                "allow": {
                    "pkcs11_functions": allow_a,
                    "tokens": ["ProxyTestToken"],
                },
            },
            {
                "id_type": "cert_fingerprint_sha256",
                "id": fp_b,
                "allow": {
                    "pkcs11_functions": allow_b,
                    "tokens": ["ProxyTestToken"],
                },
            },
        ],
    }
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "enforce",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        proxy_lib = _load_proxy_lib()

        env_a = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientA["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientA["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        env_b = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientB["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientB["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }

        result_a = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "-L"], env=env_a)
        assert result_a.returncode == 0, result_a.stderr

        result_a_keygen = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "--login", "--pin", "1234",
            "--keypairgen", "--key-type", "EC:prime256v1", "--label", "A-DeniedKey", "--id", "03",
        ], env=env_a)
        assert result_a_keygen.returncode != 0, result_a_keygen.stderr

        result_b_keygen = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "--login", "--pin", "1234",
            "--keypairgen", "--key-type", "EC:prime256v1", "--label", "B-AllowedKey", "--id", "04",
        ], env=env_b)
        assert result_b_keygen.returncode == 0, result_b_keygen.stderr

        result_b_sign = _run_cmd([
            "pkcs11-tool", "--module", proxy_lib, "--login", "--pin", "1234",
            "--sign", "--mechanism", "ECDSA", "--id", "01",
            "--input-file", __file__, "--output-file", os.path.join(mtls["temp_dir"], "b.sig"),
        ], env=env_b)
        assert result_b_sign.returncode != 0, result_b_sign.stderr
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_authz_denies_untrusted_ca_and_self_signed():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")

    clientA = mtls["clients"]["clientA"]
    fp_a = _openssl_fingerprint_sha256(clientA["cert"])

    policy = {
        "version": 1,
        "default": "deny",
        "clients": [
            {
                "id_type": "cert_fingerprint_sha256",
                "id": fp_a,
                "allow": {"pkcs11_functions": _authz_base_functions(), "tokens": ["ProxyTestToken"]},
            }
        ],
    }
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    temp_dir = mtls["temp_dir"]
    rogue_ca_key = os.path.join(temp_dir, "rogue_ca.key")
    rogue_ca_crt = os.path.join(temp_dir, "rogue_ca.crt")
    subprocess.run(["openssl", "genrsa", "-out", rogue_ca_key, "2048"], check=True)
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-key", rogue_ca_key,
        "-subj", "/CN=rogue-ca", "-days", "30", "-out", rogue_ca_crt,
    ], check=True)
    rogue_client = _generate_client_cert_with_ca(temp_dir, rogue_ca_key, rogue_ca_crt, "rogueClient")
    self_signed = _generate_self_signed_client_cert(temp_dir, "selfSigned")

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "enforce",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        proxy_lib = _load_proxy_lib()

        rogue_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": rogue_client["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": rogue_client["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        result = _run_cmd(["pkcs11-tool", "--module", proxy_lib, "-L"], env=rogue_env)
        assert result.returncode != 0

        self_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": self_signed["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": self_signed["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        result = _run_cmd(["pkcs11-tool", "--module", proxy_lib, "-L"], env=self_env)
        assert result.returncode != 0
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)


def test_authz_san_uri_match_requires_san():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if not _pkcs11_tool_available():
        pytest.skip("pkcs11-tool not available")

    pkcs11_lib = get_pkcs11_library_path()
    softhsm_conf = _ensure_softhsm_conf()
    mtls = _generate_mtls_materials_openssl()
    proxy_socket = f"tls://127.0.0.1:{_get_free_port_safe()}"
    authz_path = os.path.join(mtls["temp_dir"], "authz.json")
    clientA = mtls["clients"]["clientA"]

    policy = {
        "version": 1,
        "default": "deny",
        "clients": [
            {
                "id_type": "san_uri",
                "id": "spiffe://example.test/*",
                "allow": {"pkcs11_functions": _authz_base_functions(), "tokens": ["ProxyTestToken"]},
            }
        ],
    }
    with open(authz_path, "w") as f:
        json.dump(policy, f)

    daemon_env = {
        **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        "PKCS11_PROXY_AUTHZ_MODE": "enforce",
        "PKCS11_PROXY_AUTHZ_FILE": authz_path,
        "PKCS11_PROXY_AUTHZ_DEFAULT": "deny",
    }

    log_path = os.path.join(mtls["temp_dir"], "daemon.log")
    daemon_process, log_file = _start_daemon_with_logs(pkcs11_lib, daemon_env, log_path)
    try:
        _wait_for_daemon(daemon_process, log_path, proxy_socket)
        proxy_lib = _load_proxy_lib()
        client_env = {
            **{**os.environ, "SOFTHSM2_CONF": softhsm_conf},
            "PKCS11_PROXY_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": clientA["cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": clientA["key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
        result = _run_cmd(["pkcs11-tool", "--module", proxy_lib, "-L"], env=client_env)
        assert result.returncode != 0
    finally:
        _terminate_daemon(daemon_process)
        log_file.close()
        shutil.rmtree(mtls["temp_dir"], ignore_errors=True)
