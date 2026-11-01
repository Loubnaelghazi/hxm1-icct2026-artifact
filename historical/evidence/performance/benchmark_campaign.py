"""New benchmark infrastructure; imports existing constructions unchanged."""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import ssl
import statistics
import subprocess
import sys
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def project_hashes(project):
    return {str(p.relative_to(project)): digest(p.read_bytes())
            for p in project.rglob('*') if p.is_file()
            and '.venv' not in p.parts and '__pycache__' not in p.parts}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repetitions', type=int, default=30)
    parser.add_argument('--warmups', type=int, default=3)
    args = parser.parse_args()
    project = args.project.resolve()
    root = args.output.resolve()
    assert args.repetitions >= 30 and args.warmups >= 1
    sys.path.insert(0, str(project))
    from hybrid_rsa_mlkem import generate_keypair, encrypt, decrypt
    from run_experiments import _parse_sizes
    from cryptography import x509
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.primitives import serialization

    before = project_hashes(project)
    openssl = shutil.which('openssl')
    assert openssl, 'OpenSSL CLI unavailable'
    metadata_commands = []

    def inspect(command):
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        metadata_commands.append({'argv': command, 'stdout': result.stdout, 'stderr': result.stderr})
        return result.stdout

    cpuinfo = Path('/proc/cpuinfo').read_text()
    model = next((line.split(':', 1)[1].strip() for line in cpuinfo.splitlines()
                  if line.startswith('model name')), platform.processor())
    provenance = {
        'started_utc': datetime.now(timezone.utc).isoformat(),
        'command': [sys.executable, '-B', str(Path(__file__).resolve()), *sys.argv[1:]],
        'project': str(project), 'output': str(root),
        'python': sys.version, 'python_executable': sys.executable,
        'os': platform.platform(), 'uname': list(platform.uname()),
        'cpu_model': model, 'logical_cpus': os.cpu_count(),
        'cpu_affinity': sorted(os.sched_getaffinity(0)),
        'cpu_quota': Path('/sys/fs/cgroup/cpu.max').read_text().strip()
            if Path('/sys/fs/cgroup/cpu.max').exists() else None,
        'packages': {name: importlib.metadata.version(name) for name in ('cryptography', 'kyber-py')},
        'cli_openssl': inspect([openssl, 'version', '-a']),
        'cli_providers': inspect([openssl, 'list', '-providers']),
        'cryptography_backend_openssl': backend.openssl_version_text(),
        'python_ssl_openssl': ssl.OPENSSL_VERSION,
        'clock': vars(time.get_clock_info('perf_counter')),
        'project_sha256_before': before,
        'source_hashes': {}, 'metadata_commands': metadata_commands,
        'protocol': {
            'repetitions_per_operation': args.repetitions,
            'warmup_roundtrips_per_configuration': args.warmups,
            'aad_hex': b'benchmark-aad'.hex(),
            'order': 'payload size ascending; hybrid, rsa, mlkem, cms_cbc, cms_gcm; encrypt then decrypt',
            'timing_unit': 'integer nanoseconds; summaries in milliseconds',
            'warmups_recorded_but_excluded_from_summaries': True,
            'key_generation_and_payload_allocation_outside_timing': True,
            'verification_and_logging_outside_timing': True,
            'fresh_encryption_and_matching_decryption_each_roundtrip': True,
            'hxm1_boundary': 'Existing encrypt/decrypt APIs, including PEM key loading, KEM/KDF, AEAD, and HXM1 framing/parsing; no disk I/O or process startup',
            'cms_boundary': 'subprocess.run including process startup, certificate/key loading, file I/O, OAEP, symmetric cipher and DER; plaintext comparison outside timer',
            'cms_options': 'Unchanged from existing scripts: RSA-OAEP defaults, -aes256 or -aes-256-gcm, -binary, DER',
            'failure_policy': 'Record failure and elapsed time separately; no retries or outlier removal; failed samples excluded from successful timing summaries',
            'hxm1_and_cms_rsa_keys': 'Different keys, both RSA-3072; one fixed key per implementation throughout campaign',
        },
    }
    sources = root/'sources'
    sources.mkdir()
    for relative in ('hybrid_rsa_mlkem.py', 'run_experiments.py', 'requirements.txt',
                     'openssl_cms_bench/bench_openssl_cms.py',
                     'openssl_cms_bench/bench_openssl_cms_gcm.py'):
        data = (project/relative).read_bytes()
        dest = sources/relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as stream:
            stream.write(data)
        provenance['source_hashes'][relative] = digest(data)
    provenance['source_hashes']['benchmark_campaign.py'] = digest(Path(__file__).read_bytes())

    assets = root/'assets'
    assets.mkdir(mode=0o700)
    for name in ('cert.pem', 'rsa_priv.pem'):
        data = (project/'openssl_cms_bench'/name).read_bytes()
        fd = os.open(assets/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    cert = x509.load_pem_x509_certificate((assets/'cert.pem').read_bytes())
    cms_private = serialization.load_pem_private_key((assets/'rsa_priv.pem').read_bytes(), password=None)
    assert cert.public_key().key_size == cms_private.key_size == 3072
    assert cert.public_key().public_numbers() == cms_private.public_key().public_numbers()
    public, private = generate_keypair(3072)
    fd = os.open(assets/'hxm1_private.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(private.to_json())
    with (assets/'hxm1_public.json').open('x') as stream:
        stream.write(public.to_json())
    provenance['asset_sha256'] = {p.name: digest(p.read_bytes()) for p in assets.iterdir()}
    save(root/'provenance.json', provenance)

    raw_rows = []
    failures = []
    with (root/'raw_samples.jsonl').open('x') as raw, (root/'failures.jsonl').open('x') as failed:
        def record(row):
            raw_rows.append(row)
            raw.write(json.dumps(row, sort_keys=True)+'\n')
            raw.flush()
            if row['status'] != 'PASS':
                failures.append(row)
                failed.write(json.dumps(row, sort_keys=True)+'\n')
                failed.flush()

        for size_name, message in _parse_sizes(None).items():
            for mode in ('hybrid', 'rsa', 'mlkem', 'cms_cbc', 'cms_gcm'):
                config = f'{mode}_{len(message)}B'
                dest = root/config
                dest.mkdir()
                plain = dest/'plaintext.bin'
                with plain.open('xb') as stream:
                    stream.write(message)
                print('START', config, flush=True)
                for phase, count in (('warmup', args.warmups), ('measured', args.repetitions)):
                    for iteration in range(1, count+1):
                        common = {'configuration': config, 'implementation': mode,
                                  'payload_bytes': len(message), 'phase': phase,
                                  'iteration': iteration, 'plaintext_sha256': digest(message)}
                        package = None
                        cms = dest/f'{phase}_{iteration:03}.cms'
                        decoded = dest/f'{phase}_{iteration:03}.dec'
                        commands = {
                            'encrypt': [openssl, 'cms', '-encrypt', '-in', str(plain), '-out', str(cms), '-recip', str(assets/'cert.pem'), '-aes256' if mode == 'cms_cbc' else '-aes-256-gcm', '-binary', '-outform', 'DER', '-keyopt', 'rsa_padding_mode:oaep'],
                            'decrypt': [openssl, 'cms', '-decrypt', '-in', str(cms), '-out', str(decoded), '-recip', str(assets/'cert.pem'), '-inkey', str(assets/'rsa_priv.pem'), '-binary', '-inform', 'DER', '-keyopt', 'rsa_padding_mode:oaep'],
                        }
                        for operation in ('encrypt', 'decrypt'):
                            row = dict(common, operation=operation)
                            if mode.startswith('cms_'):
                                row['command'] = commands[operation]
                            else:
                                row['api'] = f'hybrid_rsa_mlkem.{operation}({mode!r}, bundle, data, aad=b"benchmark-aad")'
                            elapsed = None
                            started = time.perf_counter_ns()
                            try:
                                if mode.startswith('cms_'):
                                    process = subprocess.run(commands[operation], check=True, capture_output=True)
                                    elapsed = time.perf_counter_ns()-started
                                    row.update(returncode=process.returncode, stderr=process.stderr.decode(errors='replace'))
                                    result = cms.read_bytes() if operation == 'encrypt' else decoded.read_bytes()
                                else:
                                    result = encrypt(mode, public, message, b'benchmark-aad') if operation == 'encrypt' else decrypt(mode, private, package, b'benchmark-aad')
                                    elapsed = time.perf_counter_ns()-started
                                if operation == 'encrypt':
                                    package = result
                                    row.update(ciphertext_bytes=len(result), overhead_bytes=len(result)-len(message), ciphertext_sha256=digest(result))
                                else:
                                    if result != message:
                                        raise AssertionError('decrypted plaintext mismatch')
                                    row.update(plaintext_matches=True, recovered_plaintext_sha256=digest(result))
                                row.update(elapsed_ns=elapsed, status='PASS')
                            except Exception as exc:
                                row.update(elapsed_ns=elapsed if elapsed is not None else time.perf_counter_ns()-started, status='FAIL', exception_type=type(exc).__name__, exception_message=str(exc))
                                if isinstance(exc, subprocess.CalledProcessError):
                                    row.update(returncode=exc.returncode, stderr=exc.stderr.decode(errors='replace'))
                                record(row)
                                break
                            record(row)
                print('FINISHED', config, flush=True)

    grouped = defaultdict(list)
    for row in raw_rows:
        if row['phase'] == 'measured' and row['status'] == 'PASS':
            grouped[row['configuration'], row['operation']].append(row['elapsed_ns']/1_000_000)
    summaries = []
    for (config, operation), values in sorted(grouped.items()):
        summaries.append({'configuration': config, 'operation': operation, 'n': len(values),
                          'median_ms': statistics.median(values), 'mean_ms': statistics.fmean(values),
                          'sample_stdev_ms': statistics.stdev(values), 'min_ms': min(values), 'max_ms': max(values)})
    save(root/'summary.json', {'summaries': summaries, 'failure_count': len(failures), 'warmup_rows': sum(r['phase']=='warmup' for r in raw_rows), 'measured_rows': sum(r['phase']=='measured' for r in raw_rows)})
    save(root/'completion.json', {'finished_utc': datetime.now(timezone.utc).isoformat(), 'failure_count': len(failures), 'project_files_unchanged': project_hashes(project)==before})
    print('COMPLETED', len(raw_rows), 'rows;', len(failures), 'failures;', root, flush=True)
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
