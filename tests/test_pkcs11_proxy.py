import pytest
import pkcs11
import pkcs11.util.ec
from pkcs11 import Attribute, KeyType, Mechanism, KDF
import subprocess
import os
import platform
import time
import tempfile
import shutil
import atexit
from datetime import datetime, timedelta, timezone
import ipaddress
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

def get_softhsm2_conf():
    return os.path.join(os.path.dirname(__file__), "softhsm2.conf")

def get_pkcs11_library_path():
    for env_name in ("PKCS11_TEST_LIB", "PKCS11_MODULE", "SOFTHSM2_MODULE"):
        pkcs11_lib = os.getenv(env_name)
        if pkcs11_lib and os.path.exists(pkcs11_lib):
            return pkcs11_lib

    softhsm2_util = shutil.which("softhsm2-util")
    if softhsm2_util:
        softhsm_prefix = os.path.dirname(os.path.dirname(softhsm2_util))
        for path in (
            os.path.join(softhsm_prefix, "lib/softhsm/libsofthsm2.so"),
            os.path.join(softhsm_prefix, "lib/softhsm2/libsofthsm2.so"),
        ):
            if os.path.exists(path):
                return path

    default_paths = [
        "/usr/local/lib/softhsm/libsofthsm2.so", 
        "/usr/lib/softhsm/libsofthsm2.so",
    ]
    for path in default_paths:
        if os.path.exists(path):
            return path
    pytest.fail("PKCS11 library not found. Set PKCS11_TEST_LIB or install SoftHSM.")

def _write_pem(path, data):
    with open(path, "wb") as f:
        f.write(data)

def _generate_cert(subject_name, issuer_name, public_key, issuer_key, is_ca=False, san_dns=None, san_ip=None):
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(public_key)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    san_entries = []
    if san_dns:
        san_entries.append(x509.DNSName(san_dns))
    if san_ip:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(san_ip)))
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False
        )
    return builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

def _generate_mtls_materials(server_san_dns=None, server_san_ip="127.0.0.1"):
    temp_dir = tempfile.mkdtemp(prefix="pkcs11-proxy-mtls-")

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs11-proxy-test-ca")])
    ca_cert = _generate_cert(ca_name, ca_name, ca_key.public_key(), ca_key, is_ca=True)

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs11-proxy-server")])
    server_cert = _generate_cert(
        server_name,
        ca_name,
        server_key.public_key(),
        ca_key,
        san_dns=server_san_dns,
        san_ip=server_san_ip,
    )

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pkcs11-proxy-client")])
    client_cert = _generate_cert(client_name, ca_name, client_key.public_key(), ca_key)

    ca_cert_path = os.path.join(temp_dir, "ca.crt")
    server_cert_path = os.path.join(temp_dir, "server.crt")
    server_key_path = os.path.join(temp_dir, "server.key")
    client_cert_path = os.path.join(temp_dir, "client.crt")
    client_key_path = os.path.join(temp_dir, "client.key")

    _write_pem(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(server_cert_path, server_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(server_key_path, server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    _write_pem(client_cert_path, client_cert.public_bytes(serialization.Encoding.PEM))
    _write_pem(client_key_path, client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

    return {
        "temp_dir": temp_dir,
        "ca_cert": ca_cert_path,
        "server_cert": server_cert_path,
        "server_key": server_key_path,
        "client_cert": client_cert_path,
        "client_key": client_key_path,
    }

@pytest.fixture(scope="session", autouse=True)
def setup_pkcs11_proxy_lib():
    # Set SOFTHSM2_CONF path
    os.environ["SOFTHSM2_CONF"] = os.path.join(os.path.dirname(__file__), "softhsm2.conf")
    # Check if PKCS11_TEST_NO_PROXY is set
    if os.getenv("PKCS11_TEST_NO_PROXY"):
        # Use SoftHSM directly without starting pkcs11-daemon
        pkcs11_lib = get_pkcs11_library_path()
        yield pkcs11_lib
        return

    build_dir = os.path.join(os.path.dirname(__file__), "../build")
    pkcs11_daemon_path = os.path.join(build_dir, "pkcs11-daemon")
    
    # OSX uses dylib by default
    lib_extension = "dylib" if platform.system() == "Darwin" else "so"
    proxy_lib_path = os.path.join(build_dir, f"libpkcs11-proxy.{lib_extension}")
    
    if not os.path.exists(pkcs11_daemon_path):
        pytest.fail(f"pkcs11-daemon not found in {build_dir}. Ensure it is built correctly.")
    if not os.path.exists(proxy_lib_path):
        pytest.fail(f"Proxy library {proxy_lib_path} not found in {build_dir}.")

    pkcs11_lib = get_pkcs11_library_path()

    daemon_env = None
    mtls_materials = None

    if os.getenv("PKCS11_TEST_MTLS"):
        proxy_socket = "tls://127.0.0.1:2345"
        mtls_materials = _generate_mtls_materials()

        os.environ["PKCS11_PROXY_TLS_MODE"] = "cert"
        os.environ["PKCS11_PROXY_TLS_CERT_FILE"] = mtls_materials["client_cert"]
        os.environ["PKCS11_PROXY_TLS_KEY_FILE"] = mtls_materials["client_key"]
        os.environ["PKCS11_PROXY_TLS_CA_FILE"] = mtls_materials["ca_cert"]
        os.environ["PKCS11_PROXY_TLS_VERIFY_PEER"] = "true"

        daemon_env = {
            **os.environ,
            "PKCS11_DAEMON_SOCKET": proxy_socket,
            "PKCS11_PROXY_TLS_MODE": "cert",
            "PKCS11_PROXY_TLS_CERT_FILE": mtls_materials["server_cert"],
            "PKCS11_PROXY_TLS_KEY_FILE": mtls_materials["server_key"],
            "PKCS11_PROXY_TLS_CA_FILE": mtls_materials["ca_cert"],
            "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
        }
    elif os.getenv("PKCS11_TEST_TLS"):
        proxy_socket = "tls://127.0.0.1:2345"
        # Create PSK file in the same directory as this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        psk_file_name = os.path.join(script_dir, "pkcs11_tls.psk")
        # Write the PSK content to the file
        psk_content = "client:0df6c00be91c6a334589f699365b3125acb9e2232203d2e05ee61af848c103a4"
        with open(psk_file_name, "w") as f:
            f.write(psk_content)
        os.environ["PKCS11_PROXY_TLS_PSK_FILE"] = psk_file_name
        daemon_env = {**os.environ, "PKCS11_DAEMON_SOCKET": proxy_socket}
    else:
        proxy_socket = "tcp://127.0.0.1:2345"
        daemon_env = {**os.environ, "PKCS11_DAEMON_SOCKET": proxy_socket}

    if not os.getenv("PKCS11_TEST_NO_DAEMON"):
        daemon_process = subprocess.Popen([
            pkcs11_daemon_path, pkcs11_lib
        ], env=daemon_env)
        def _terminate_daemon():
            if daemon_process.poll() is None:
                daemon_process.terminate()
                try:
                    daemon_process.wait(timeout=2)
                except Exception:
                    daemon_process.kill()
        atexit.register(_terminate_daemon)
    else:
        daemon_process = None

    # Set PKCS11_PROXY_SOCKET for the proxy library to connect to the daemon
    os.environ["PKCS11_PROXY_SOCKET"] = proxy_socket
    
    time.sleep(0.5)
    yield proxy_lib_path
    if daemon_process:
        pass
    if mtls_materials:
        shutil.rmtree(mtls_materials["temp_dir"], ignore_errors=True)

@pytest.fixture
def pkcs11_session(setup_pkcs11_proxy_lib):
    lib = pkcs11.lib(setup_pkcs11_proxy_lib)
    token = lib.get_token(token_label="ProxyTestToken")
    
    with token.open(user_pin="1234", rw=True) as session:
        yield session

def test_mtls_env_setup():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    assert os.getenv("PKCS11_PROXY_TLS_MODE") == "cert"
    assert os.path.exists(os.environ["PKCS11_PROXY_TLS_CERT_FILE"])
    assert os.path.exists(os.environ["PKCS11_PROXY_TLS_KEY_FILE"])
    assert os.path.exists(os.environ["PKCS11_PROXY_TLS_CA_FILE"])

def test_mtls_hostname_mismatch_rejected():
    if not os.getenv("PKCS11_TEST_MTLS"):
        pytest.skip("mTLS not enabled")
    if os.getenv("PKCS11_TEST_NO_DAEMON"):
        pytest.skip("daemon disabled")

    build_dir = os.path.join(os.path.dirname(__file__), "../build")
    pkcs11_daemon_path = os.path.join(build_dir, "pkcs11-daemon")
    lib_extension = "dylib" if platform.system() == "Darwin" else "so"
    proxy_lib_path = os.path.join(build_dir, f"libpkcs11-proxy.{lib_extension}")
    if not os.path.exists(pkcs11_daemon_path) or not os.path.exists(proxy_lib_path):
        pytest.skip("pkcs11-daemon or proxy library not built")

    mtls_materials = _generate_mtls_materials(server_san_dns="wrong.host", server_san_ip=None)
    proxy_socket = "tls://127.0.0.1:2346"

    daemon_env = {
        **os.environ,
        "PKCS11_DAEMON_SOCKET": proxy_socket,
        "PKCS11_PROXY_TLS_MODE": "cert",
        "PKCS11_PROXY_TLS_CERT_FILE": mtls_materials["server_cert"],
        "PKCS11_PROXY_TLS_KEY_FILE": mtls_materials["server_key"],
        "PKCS11_PROXY_TLS_CA_FILE": mtls_materials["ca_cert"],
        "PKCS11_PROXY_TLS_VERIFY_PEER": "true",
    }

    old_env = os.environ.copy()
    daemon_process = subprocess.Popen([pkcs11_daemon_path, get_pkcs11_library_path()], env=daemon_env)
    try:
        os.environ["PKCS11_PROXY_SOCKET"] = proxy_socket
        os.environ["PKCS11_PROXY_TLS_MODE"] = "cert"
        os.environ["PKCS11_PROXY_TLS_CERT_FILE"] = mtls_materials["client_cert"]
        os.environ["PKCS11_PROXY_TLS_KEY_FILE"] = mtls_materials["client_key"]
        os.environ["PKCS11_PROXY_TLS_CA_FILE"] = mtls_materials["ca_cert"]
        os.environ["PKCS11_PROXY_TLS_VERIFY_PEER"] = "true"

        time.sleep(0.5)
        with pytest.raises(Exception):
            lib = pkcs11.lib(proxy_lib_path)
            token = lib.get_token(token_label="ProxyTestToken")
            with token.open(user_pin="1234", rw=True):
                pass
    finally:
        if daemon_process.poll() is None:
            daemon_process.terminate()
            try:
                daemon_process.wait(timeout=2)
            except Exception:
                daemon_process.kill()
        shutil.rmtree(mtls_materials["temp_dir"], ignore_errors=True)
        os.environ.clear()
        os.environ.update(old_env)

def test_tls_psk_uses_identity_from_file(pkcs11_session):
    if not os.getenv("PKCS11_TEST_TLS"):
        pytest.skip("PSK TLS not enabled")
    mechanisms = pkcs11_session.token.slot.get_mechanisms()
    assert mechanisms is not None

def test_rsa_generate_keypair(pkcs11_session):
    public_key, private_key = pkcs11_session.generate_keypair(
        KeyType.RSA, 2048, store=True, label="TestRSAKey"
    )
    assert public_key is not None
    assert private_key is not None

def test_rsa_encrypt_decrypt(pkcs11_session):
    public_key, private_key = pkcs11_session.generate_keypair(
        KeyType.RSA, 2048, store=True, label="TestRSAKey"
    )
    message = b"Secret Message"
    encrypted = public_key.encrypt(message, mechanism=Mechanism.RSA_PKCS)
    decrypted = private_key.decrypt(encrypted, mechanism=Mechanism.RSA_PKCS)

    assert message == decrypted

def test_ecdsa_key_load_and_sign_verify(pkcs11_session):
    # Load the private key created during setup by label
    private_key = pkcs11_session.get_key(
        label="ProxyTestExistingECKey",
        key_type=KeyType.EC,
        object_class=pkcs11.ObjectClass.PRIVATE_KEY
    )
    assert private_key is not None, "Failed to load private key"

    # Load the corresponding public key by label
    public_key = pkcs11_session.get_key(
        label="ProxyTestExistingECKey",
        key_type=KeyType.EC,
        object_class=pkcs11.ObjectClass.PUBLIC_KEY
    )
    assert public_key is not None, "Failed to load public key"

    # Message to sign
    message = b"Message to be signed using ECDSA"

    # Sign the message using the private key
    signature = private_key.sign(
        message,
        mechanism=Mechanism.ECDSA
    )
    assert signature is not None, "Signature generation failed"

    # Verify the signature using the public key
    is_valid = public_key.verify(
        message,
        signature,
        mechanism=Mechanism.ECDSA
    )
    assert is_valid, "Signature verification failed"

def test_ecdh_derive_key(pkcs11_session):
    # Generate Alice's EC key pair in PKCS#11
    ecparams = pkcs11_session.create_domain_parameters(
        pkcs11.KeyType.EC, {
            pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters('secp256r1'),
        }, local=True)
    alice_public_key, alice_private_key = ecparams.generate_keypair(store=True, label="TestECKey")
    alices_value_raw = alice_public_key[Attribute.EC_POINT]
    # Strip first two extra bytes
    alices_value = alices_value_raw[2:]

    # Generate Bob's EC key pair in `cryptography`
    bob_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    bob_public_key = bob_private_key.public_key()

    # Export Bob's public key to DER format and decode the EC point to match PKCS#11 format
    bobs_value = bob_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Get Alice's secret
    session_key_alice = alice_private_key.derive_key(
        KeyType.AES, 256,
        mechanism_param=(KDF.NULL, None, bobs_value)
    )

    # Bob derives the shared secret using Alice's public value in `cryptography`
    shared_secret_bob = bob_private_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), alices_value))

    # Use AES-CBC for encryption with Alice's session key
    iv = os.urandom(16)
    plaintext = b"Test message for ECDH key agreement verification"

    # Alist encrypts the key - AES_CBC_PAD is default
    ciphertext = session_key_alice.encrypt(plaintext, mechanism_param=iv)

    # Bob tries to decrypt the message using his derived key
    cipher = Cipher(algorithms.AES(shared_secret_bob), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_text_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted text
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_text_padded) + unpadder.finalize()

    # Verify that the decrypted text matches the original plaintext
    assert decrypted_text == plaintext

def test_mechanism_list_contains_ecdh(pkcs11_session):
    mechanisms = pkcs11_session.token.slot.get_mechanisms()
    assert Mechanism.ECDH1_DERIVE in mechanisms, "ECDH1_DERIVE mechanism is not supported by the token"
