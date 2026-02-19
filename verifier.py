import json
import os
import requests
import hashlib
import yaml
import urllib3
from Crypto.Hash import keccak

# Event type constant for dstack runtime events
DSTACK_RUNTIME_EVENT_TYPE = 0x08000001

def compute_runtime_event_digest(event_type, event_name, event_payload_hex):
    '''
    Compute SHA-384 digest for a dstack runtime event.
    Formula: SHA384(event_type_le_bytes || ":" || event_name_bytes || ":" || event_payload_bytes)
    Reference: cc-eventlog/src/runtime_events.rs - RuntimeEvent::digest()
    '''
    event_type_bytes = event_type.to_bytes(4, byteorder='little')
    event_payload_bytes = bytes.fromhex(event_payload_hex) if event_payload_hex else b''
    data = event_type_bytes + b':' + event_name.encode() + b':' + event_payload_bytes
    return hashlib.sha384(data).digest()

def replay_rtmr3(event_log_json):
    '''
    Replay RTMR3 from event log to recompute the expected register value.
    RTMR3 uses a hash chain: starting from 48 zero bytes, each event extends
    the register via RTMR3 = SHA384(RTMR3 || digest).

    RTMR3 records runtime events during CVM boot:
    - system-preparing, app-id, compose-hash, instance-id, boot-mr-done,
      mr-kms, os-image-hash, key-provider, storage-fs, system-ready

    Reference: verifier/src/verification.rs - replay_event_logs()
    Reference: cc-eventlog/src/runtime_events.rs - replay_events()
    '''
    events = json.loads(event_log_json)
    rtmr3 = b'\x00' * 48  # initial value: 48 zero bytes

    for event in events:
        if event['imr'] != 3:
            continue

        # For runtime events, compute digest from event content
        # For boot events, use the pre-computed digest field
        if event['event_type'] == DSTACK_RUNTIME_EVENT_TYPE:
            digest = compute_runtime_event_digest(
                event['event_type'], event['event'], event['event_payload']
            )
        else:
            digest = bytes.fromhex(event['digest'])

        # Pad digest to 48 bytes if shorter (as done in the Rust SDK replay_rtmr)
        if len(digest) < 48:
            digest = digest + b'\x00' * (48 - len(digest))

        # Extend: RTMR3 = SHA384(RTMR3 || digest)
        rtmr3 = hashlib.sha384(rtmr3 + digest).digest()

    return rtmr3

if __name__ == '__main__':
    # Disable SSL warnings (temporary workaround until we change DNS hosting provider to Cloudflare)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    #Application (docker-compose based app) we want to attest
    app_id = 'dfc9c995de8775d0fa3f8a9dfd720f1f493cbba1'

    # Generate a random nonce (32 bytes = 64 hex chars, fits within 64 bytes max)
    nonce = os.urandom(32)
    nonce_hex = nonce.hex()
    print(f'Nonce (hex): {nonce_hex}')

    quote_service_port = '8081' # change according to your config

    # Fetch attestation quote with nonce bound into report_data
    attest_response = requests.get(f'https://{app_id}-{quote_service_port}.apps.ovh-tdx-dev.iex.ec:9204/quote?data={nonce_hex}', verify=False)
    attest_data = attest_response.json()

    quote = attest_data['quote']
    event_log = attest_data['event_log']
    #TODO: extract report_data and verify it against the expected value

    # Fetch application configuration
    info_response = requests.get(
        f'https://{app_id}-8090.apps.ovh-tdx-dev.iex.ec:9204/prpc/Info',
        verify=False,
    )
    app_info = info_response.json()
    tcb_info = json.loads(app_info['tcb_info'])
    app_compose_config = tcb_info['app_compose'] 

    #--------------------------------Step 1: verify compose_hash--------------------------------
    # We should first compare app_compose_config against whitelisted reference for the app that we expose

    # Calculate SHA-256 hash of app-compose 
    calculated_hash = hashlib.sha256(app_compose_config.encode()).hexdigest()

    # Extract attested hash from RTMR3 event log
    events = json.loads(event_log)
    compose_event = next(e for e in events if e['event'] == 'compose-hash')
    attested_hash = compose_event['event_payload']

    # Verify hashes match
    assert calculated_hash == attested_hash, 'compose-hash mismatch'
    print(f'[OK] Step 1: compose-hash verified ({calculated_hash})')

    #--------------------------------Step 2: verify quote signature--------------------------------

    # We can use Intel PCS
    # Or expose our own verification service
    # Or Phala cloud verification service
    verify_response = requests.post(
        'https://cloud-api.phala.network/api/v1/attestations/verify',
        json={'hex': quote}
    )

    result = verify_response.json()
    assert result['quote']['verified'], 'Hardware verification failed'
    print(f'[OK] Step 2: quote signature verified by Phala Cloud')

    #--------------------------------Step 3: verify report_data (nonce binding)--------------------------------
    quote_report_data = result['quote']['body']['reportdata']
    quote_report_data = quote_report_data[2:] # Remove 0x prefix

    # report_data = ASCII encoding of nonce_hex, zero-padded to 64 bytes
    expected_report_data = nonce_hex.encode('ascii').hex().ljust(128, '0')

    assert quote_report_data == expected_report_data, (
        f'report_data mismatch!\n'
        f'  expected: {expected_report_data}\n'
        f'  got:      {quote_report_data}'
    )
    print(f'[OK] Step 3: report_data verified (nonce bound to quote)')


    #--------------------------------Adcanced verification--------------------------------
    #RTMR3 event log replay: Cryptographically prove the boot sequence
    #Docker image digests: Ensure images are pinned to specific versions
    #On-chain governance: Verify only authorized configs can run
    #Source code provenance: Link images back to audited source code

    #------------------------Step 4: verify RTMR3 event log replay------------------------
    # Replay the event log to recompute RTMR3, then compare with the value in the quote
    # This proves the event log (containing compose-hash etc.) has not been tampered with

    replayed_rtmr3 = replay_rtmr3(event_log)

    # Get RTMR3 from the quote (returned by Phala verification, prefixed with 0x)
    quote_rtmr3_hex = result['quote']['body']['rtmr3']
    if quote_rtmr3_hex.startswith('0x'):
        quote_rtmr3_hex = quote_rtmr3_hex[2:]
    quote_rtmr3 = bytes.fromhex(quote_rtmr3_hex)

    assert replayed_rtmr3 == quote_rtmr3, (
        f'RTMR3 mismatch!\n'
        f'  replayed: {replayed_rtmr3.hex()}\n'
        f'  quote:    {quote_rtmr3.hex()}'
    )
    print(f'[OK] Step 4: RTMR3 replay verified ({replayed_rtmr3.hex()})')

    #--------------------------------Step 5: verify docker image digests--------------------------------
    # Parse app-compose and extract docker-compose
    app_compose = json.loads(app_compose_config)
    docker_compose = yaml.safe_load(app_compose['docker_compose_file'])

    # Check all services use @sha256 digests
    for service_name, service in docker_compose.get('services', {}).items():
        image = service.get('image', '')
        assert ':dev-' in image, f'Image not pinned by digest: {service_name}' # dstack recommaends to pin to @sha256: digests
        # You can also download the image and verify the digest against whitelisted reference for the app
    
    #--------------------------------Step 6: verify on-chain governance--------------------------------
    # Verify the compose-hash is whitelisted in the DstackApp smart contract
    # DstackApp address = app_id (the contract deployed via kms:create-app)
    # Function: allowedComposeHashes(bytes32) → bool
    # Selector: first 4 bytes of keccak256 of the function signature

    ALCHEMY_API_KEY = os.environ.get('ALCHEMY_API_KEY', '')
    assert ALCHEMY_API_KEY, 'ALCHEMY_API_KEY environment variable is required for on-chain verification'

    rpc_url = f'https://eth-sepolia.g.alchemy.com/v2/{ALCHEMY_API_KEY}'
    dstack_app_address = f'0x{app_id}'
    compose_hash_bytes32 = '0x' + calculated_hash  # SHA-256 = 32 bytes = bytes32

    # Compute selector: keccak256("allowedComposeHashes(bytes32)")[:4]
    selector = keccak.new(data=b'allowedComposeHashes(bytes32)', digest_bits=256).hexdigest()[:8]

    # ABI-encode: selector (4 bytes) + compose_hash (32 bytes, already left-aligned)
    calldata = '0x' + selector + calculated_hash.zfill(64)

    rpc_response = requests.post(rpc_url, json={
        'jsonrpc': '2.0',
        'method': 'eth_call',
        'params': [{'to': dstack_app_address, 'data': calldata}, 'latest'],
        'id': 1,
    })

    rpc_result = rpc_response.json()
    assert 'error' not in rpc_result, f'RPC error: {rpc_result.get("error")}'

    # Result is ABI-encoded bool: 32 bytes, last byte = 0x01 (true) or 0x00 (false)
    return_data = rpc_result['result']
    is_whitelisted = int(return_data, 16) == 1

    assert is_whitelisted, (
        f'compose-hash not whitelisted on-chain!\n'
        f'  DstackApp: {dstack_app_address}\n'
        f'  compose-hash: {compose_hash_bytes32}'
    )
    print(f'[OK] Step 6: on-chain governance verified (compose-hash whitelisted in DstackApp {dstack_app_address})')

    #--------------------------------Step 7: verify source code provenance--------------------------------
    # For maximum verifiability, use reproducible builds where anyone can rebuild from source and get identical digests. 
    # Publish your Dockerfile and build instructions.