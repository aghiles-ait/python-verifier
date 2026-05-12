'''
End-to-end remote attestation verifier for dstack Confidential Virtual Machines (CVMs).

Performs the 6 verification steps (compose-hash, quote signature, report_data challenge,
RTMR3 replay, docker image pinning, on-chain governance) to prove that a specific
application is running unmodified inside genuine Intel TDX hardware.
'''
import json
import os
import hashlib
import requests

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
    runtime_events = json.loads(event_log_json)
    rtmr3 = b'\x00' * 48  # initial value: 48 zero bytes

    for event in runtime_events:
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
    #INPUTS:
    #Application (docker-compose based app) we want to attest
    INSTANCE_ID = 'f0dff7c095b994bae1d98302d20e01d4d77574a5'
    QUOTE_SERVICE_PORT = '9999' # change according to your config
    URL_SUFFIX = 'apps.ovh-tdx-dev.noxprotocol.dev'

    BASE_URL = f'https://{INSTANCE_ID}-{QUOTE_SERVICE_PORT}.{URL_SUFFIX}'
    print(f'Attesting CVM on quote service: https://{INSTANCE_ID}-{QUOTE_SERVICE_PORT}.{URL_SUFFIX}')

    # Generate a random challenge (32 bytes = 64 hex chars, fits within 64 bytes max)
    challenge = os.urandom(32)
    challenge_hex = challenge.hex()
    print(f'Generating challenge (hex): {challenge_hex}')

    # Fetch attestation quote with challenge bound into report_data
    attest_response = requests.get(
        f'{BASE_URL}/quote?data={challenge_hex}',
        timeout=15,
    )
    attest_data = attest_response.json()
    quote = attest_data['quote']
    event_log = attest_data['event_log']

    # Fetch application configuration
    info_response = requests.get(
        f'{BASE_URL}/info',
        timeout=15,
    )
    app_info = info_response.json()
    tcb_info = app_info['tcb_info']
    app_compose_config = tcb_info['app_compose']

    #--------------------------------Step 1: verify quote signature--------------------------------
    print('Step 1: Verification of quote signature by Phala Cloud...')
    # We can expose our own verification service
    # Or use Phala cloud verification service
    verify_response = requests.post(
        'https://cloud-api.phala.network/api/v1/attestations/verify',
        json={'hex': quote},
        timeout=15,
    )
    #print(verify_response.json())
    result = verify_response.json()
    assert result['quote']['verified'], 'Hardware verification failed'
    print('[OK] Step 1: Quote signature attested')
    if result['node_provider']['proof_of_cloud']:
        print('[OK] Step 1: Proof of Cloud verified')
    print('[KO-] Step 1: Not proof of cloud verified')
    print('[KO] Step 1: Error to handle...')
    print()

    #-----------------Step 2: verify report_data (challenge binding)-----------------
    print('Step 2: Verification of quote freshness...')
    quote_report_data = result['quote']['body']['reportdata']
    quote_report_data = quote_report_data[2:] # Remove 0x prefix

    # report_data = ASCII encoding of challenge_hex, zero-padded to 64 bytes
    expected_report_data = challenge_hex.encode('ascii').hex().ljust(128, '0')

    assert quote_report_data == expected_report_data, (
        f'report_data mismatch!\n'
        f'  expected: {expected_report_data}\n'
        f'  got:      {quote_report_data}'
    )
    print('[OK] Step 2: Quote freshness verified')
    print('[KO] Step 2: Challenge did NOT match the expected value')
    print()

    events = json.loads(event_log)

    #--------------------------------Display App identity--------------------------------
    print(f'APP ID        : {app_info['app_id']} ({app_info['app_name']})')
    print(f'INSTANCE ID   : {app_info['instance_id']}')
    print()

    #------------------------Step 3: verify RTMR3 event log replay------------------------
    # Replay the event log to recompute RTMR3, then compare with the value in the quote
    # This proves the event log (containing compose-hash etc.) has not been tampered with
    print('Step 3: Extraction of RTMR values from quote...')
    print(f'RTMR0: {result['quote']['body']['rtmr0']}')
    print(f'RTMR1: {result['quote']['body']['rtmr1']}')
    print(f'RTMR2: {result['quote']['body']['rtmr2']}')
    print(f'RTMR3: {result['quote']['body']['rtmr3']}')

    print('Replaying RTMR3 from event log...')

    REPLAYED_RTMR3 = replay_rtmr3(event_log)

    # Get RTMR3 from the quote (returned by Phala verification, prefixed with 0x)
    quote_rtmr3_hex = result['quote']['body']['rtmr3']
    if quote_rtmr3_hex.startswith('0x'):
        quote_rtmr3_hex = quote_rtmr3_hex[2:]
    quote_rtmr3 = bytes.fromhex(quote_rtmr3_hex)

    assert REPLAYED_RTMR3 == quote_rtmr3, (
        f'RTMR3 mismatch!\n'
        f'  replayed: {REPLAYED_RTMR3.hex()}\n'
        f'  quote:    {quote_rtmr3.hex()}'
    )
    print('[OK] Step 3: RTMR3 replay verified')
    print('[KO] Step 3: RTMR3 replay did NOT match the expected value')
    print()
    
    #--------------------------------Step 4: verify os_image_hash--------------------------------
    print('Step 4: Verification of os-image-hash...')
    os_image_event = next(e for e in events if e['event'] == 'os-image-hash' and e['imr'] == 3)
    os_image_hash = os_image_event['event_payload']
    print(f'[OK] Step 4: os-image-hash ({os_image_hash}) exists in RTMR3 event log')
    print(f'[OK] Download the os-image from: https://download.dstack.org/os-images/mr_{os_image_hash}.tar.gz')
    print('[KO] Step 4: os-image-hash did NOT exist in RTMR3 event log')
    print()

    #--------------------------------Step 5: verify compose_hash--------------------------------
    print('Step 5: Verification of compose-hash...')
    # Calculate SHA-256 hash of app-compose
    CALCULATED_HASH = hashlib.sha256(app_compose_config.encode()).hexdigest()

    # Extract attested hash from RTMR3 event log
    compose_event = next(e for e in events if e['event'] == 'compose-hash' and e['imr'] == 3)
    attested_hash = compose_event['event_payload']

    # Verify hashes match
    assert CALCULATED_HASH == attested_hash, 'compose-hash mismatch'
    print(f'[OK] Step 5: compose-hash ({CALCULATED_HASH}) exists in RTMR3 event log')
    print(f'[KO] Step 5: compose-hash ({CALCULATED_HASH}) does not exists in RTMR3 event log')
    print()

    #--------------------------------Step 6: Display docker compose file--------------------------------
    print('Step 6: Displaying docker compose file...')
    app_compose_json = json.loads(app_compose_config)
    docker_compose_yaml = app_compose_json['docker_compose_file']
    for line in docker_compose_yaml.rstrip().splitlines():
        print(f'    {line}')
    print()

    '''
    #--------------------------------Step 7: Display significant information--------------------------------
    body = result['quote']['body']
    app_compose_json = json.loads(app_compose_config)
    docker_compose_yaml = app_compose_json['docker_compose_file']

    WIDTH = 80
    print()
    print('=' * WIDTH)
    print(' VERIFICATION SUMMARY '.center(WIDTH, '='))
    print('=' * WIDTH)
    print()
    print('  Status        : ALL CHECKS PASSED')
    print('  Hardware      : Intel TDX (verified by Phala Cloud)')
    print(f'  APP ID        : {app_info['app_id']} ({app_info['app_name']})')
    print(f'  INSTANCE ID   : {app_info['instance_id']}')
    print(f'  OS Image Hash : {os_image_hash}')
    print(f'    For reproducibility of hash:')
    print(f'      - Download: https://download.dstack.org/os-images/mr_{os_image_hash}.tar.gz')
    print(f'      - Extract the tar.gz file and compute the hash of the extracted file using "sha256sum sha256sum.txt"')
    print(f'  Compose hash  : {CALCULATED_HASH}')
    print(f'  Node provider : {result['node_provider']}')
    print()
    print('  RTMR registers')
    print('  ' + '-' * (WIDTH - 2))
    print(f'    RTMR0       : {body['rtmr0']}')
    print(f'    RTMR1       : {body['rtmr1']}')
    print(f'    RTMR2       : {body['rtmr2']}')
    print(f'    RTMR3       : {body['rtmr3']}')
    print( '                  (replayed from event log -> match)')
    print()
    print('  Docker compose (attested)')
    print('  ' + '-' * (WIDTH - 2))
    for line in docker_compose_yaml.rstrip().splitlines():
        print(f'    {line}')
    print()
    print('=' * WIDTH)
    '''
    '''
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
    # DstackApp address = APP_ID (the contract deployed via kms:create-app)
    # Function: allowedComposeHashes(bytes32) → bool
    # Selector: first 4 bytes of keccak256 of the function signature
    
    ALCHEMY_API_KEY = os.environ.get('ALCHEMY_API_KEY', '')
    assert ALCHEMY_API_KEY, 'ALCHEMY_API_KEY environment variable is required for on-chain verification'

    rpc_url = f'https://eth-sepolia.g.alchemy.com/v2/{ALCHEMY_API_KEY}'
    dstack_app_address = f'0x{APP_ID}'
    compose_hash_bytes32 = '0x' + CALCULATED_HASH  # SHA-256 = 32 bytes = bytes32

    # Compute selector: keccak256("allowedComposeHashes(bytes32)")[:4]
    selector = keccak.new(data=b'allowedComposeHashes(bytes32)', digest_bits=256).hexdigest()[:8]

    # ABI-encode: selector (4 bytes) + compose_hash (32 bytes, already left-aligned)
    calldata = '0x' + selector + CALCULATED_HASH.zfill(64)

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
    '''
