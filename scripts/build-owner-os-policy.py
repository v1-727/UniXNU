#!/usr/bin/env python3
"""Sign and fully verify an original OS or SystemOS image without expanding the UDIF.

The raw disk comes from a read-only hdiutil attachment on macOS (checked with diskutil) and from udif.py on
other hosts, which gives the same bytes. The volume UUID is a fact of the pinned IPSW member, as in the
kernel's owner patches. A policy that already matches its source and owner key is kept.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import plistlib
import stat
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
COMPONENTS = {
    'os': dict(member='044-76040-038.dmg', udif=True, image_bytes=6077580800,
               source_sha256='3f99b859c9728379110b66657c7b15285bcb1925ad8b5726542e2cdcf8b1028d',
               volume_uuid='04769D26-2CA0-4825-B443-E2E5F88300F2', mount='os-mount'),
    'systemos': dict(member='044-76034-038.dmg', udif=False, image_bytes=3303014400,
                     source_sha256='b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f',
                     volume_uuid='8846FE78-2910-4297-AF97-D59BB6F8FC16'),
}
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--component', choices=sorted(COMPONENTS), default='os')
args = parser.parse_args()
spec = COMPONENTS[args.component]
source = ROOT / '.cache/firmware/target-volumes' / spec['member']
out = ROOT / ('build/verified-root-' + args.component)
host = ROOT / 'build/verified-root-host'
library = host / ('verified-root.dylib' if platform.system() == 'Darwin' else 'verified-root.so')
expected_uuid = uuid.UUID(spec['volume_uuid'])
if not source.is_file():
    raise SystemExit(f'Require the existing exact original {args.component} input {source}')
digest = hashlib.sha256()
with source.open('rb') as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(chunk)
    stream.seek(-512, 2)
    if (stream.read(4) == b'koly') != spec['udif']:
        raise SystemExit('Expected the actual original ' + ('UDIF' if spec['udif'] else 'raw') + ' image')
if digest.hexdigest() != spec['source_sha256']:
    raise SystemExit(f'The image must be the exact supplied iPad7,1 {args.component} member')
if not library.is_file() or not (host / 'keys/owner.pem').is_file():
    # VerifiedRoot's own check creates the owner keys and the host verifier, and exercises both.
    openssl = Path(subprocess.check_output(['brew', '--prefix', 'openssl@3'], text=True).strip()) \
        if platform.system() == 'Darwin' else Path('/usr')
    subprocess.run([sys.executable, ROOT / 'kits/VerifiedRoot/tests/check.py', '--output', host,
                    '--openssl-prefix', openssl], check=True)
keys = host / 'keys'
spec_path = ROOT / 'kits/VerifiedRoot/tools/manifest.py'
loader = importlib.util.spec_from_file_location('verified_manifest', spec_path)
manifest = importlib.util.module_from_spec(loader)
loader.loader.exec_module(manifest)
anchor_sha256 = hashlib.sha256(manifest.public_anchor(keys / 'owner-public.pem')).hexdigest()
report_path = out / 'verification.json'
if report_path.is_file():
    previous = json.loads(report_path.read_text())
    if (previous.get('source_compressed_sha256') == digest.hexdigest() and previous.get('trusted_key_sha256') == anchor_sha256
            and previous.get('volume_uuid') == str(expected_uuid).upper() and previous.get('real_c_signature_and_block_verification')):
        print(f'PASS: {args.component} policy already verified for this source and owner key')
        raise SystemExit(0)


class Chunks:
    """File-like reader over the raw-disk chunks of udif.py."""

    def __init__(self, chunks):
        self.chunks, self.buffer = iter(chunks), b''

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, size):
        while len(self.buffer) < size:
            chunk = next(self.chunks, None)
            if chunk is None:
                break
            self.buffer += chunk
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data


def open_raw():
    if not spec['udif']:
        return source.open('rb', buffering=1024 * 1024)
    if platform.system() == 'Darwin':
        return disk.open('rb', buffering=1024 * 1024)
    from unixnu import udif
    return Chunks(udif.Image(source).blocks())


if spec['udif'] and platform.system() == 'Darwin':
    volume = ROOT / '.cache/firmware/target-volumes' / spec['mount']
    images = plistlib.loads(subprocess.check_output(['hdiutil', 'info', '-plist']))['images']
    found = [i for i in images if Path(i['image-path']).resolve() == source.resolve() and i.get('writeable') is False]
    if len(found) != 1:
        raise SystemExit('Require one existing exact read-only image attachment')
    entities = found[0]['system-entities']
    whole = [e['dev-entry'] for e in entities if e.get('content-hint') == 'GUID_partition_scheme']
    if len(whole) != 1:
        raise SystemExit('Require one actual whole virtual media mapping')
    info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', whole[0]]))
    volume_info = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', volume]))
    if (info.get('BusProtocol') != 'Disk Image' or info.get('Writable') is not False or
            info.get('DeviceNode') != whole[0] or info.get('TotalSize') != spec['image_bytes'] or
            volume_info.get('VolumeUUID') != str(expected_uuid).upper() or volume_info.get('Writable') is not False or
            volume_info.get('DeviceNode') not in [e['dev-entry'] for e in entities]):
        raise SystemExit('Only the actual matching read-only Disk Image volume is accepted')
    disk = Path('/dev/r' + Path(whole[0]).name)
    if not stat.S_ISCHR(disk.stat().st_mode):
        raise SystemExit('Require the verified virtual-media raw character device')
    host_protocol = 'Disk Image'
else:
    host_protocol = 'udif.py' if spec['udif'] else 'raw image file'
with open_raw() as stream:
    record = manifest.make(stream, spec['image_bytes'], keys / 'owner.pem', keys / 'owner-public.pem', expected_uuid, 1, out)


class View(ctypes.Structure):
    _fields_ = [('hashes', ctypes.c_void_p), ('image_bytes', ctypes.c_uint64), ('block_count', ctypes.c_uint64),
                ('generation', ctypes.c_uint64), ('volume_uuid', ctypes.c_uint8 * 16), ('image_sha256', ctypes.c_uint8 * 32)]


native = ctypes.CDLL(str(library))
native.vr_host_open.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_uint64, ctypes.POINTER(View)]
native.vr_host_block.argtypes = [ctypes.POINTER(View), ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t]
encoded = ctypes.create_string_buffer((out / 'manifest.bin').read_bytes())
anchor = ctypes.create_string_buffer((out / 'trusted-key.bin').read_bytes())
view = View()
if native.vr_host_open(encoded, len(encoded) - 1, anchor, 1, ctypes.byref(view)) or bytes(view.volume_uuid) != expected_uuid.bytes:
    raise SystemExit('Real C signature/volume authentication failed')
complete = hashlib.sha256()
indices = [0, 1, view.block_count // 2, view.block_count - 1]
samples, lengths = [], []
with open_raw() as stream:
    for index in range(view.block_count):
        block = stream.read(min(4096, view.image_bytes - index * 4096))
        if native.vr_host_block(ctypes.byref(view), index, block, len(block)) != 0:
            raise SystemExit('Actual C block verification failed at ' + str(index))
        complete.update(block)
        if index in indices:
            samples.append(block.ljust(4096, b'\0'))
            lengths.append(len(block))
    if stream.read(1):
        raise SystemExit('Virtual media exceeded its authenticated exact bounds')
if complete.digest() != bytes(view.image_sha256) or complete.hexdigest() != record['image_sha256']:
    raise SystemExit(f'Actual complete original {args.component} digest differs')
(out / 'original-samples.bin').write_bytes(b''.join(samples))
report = dict(image_bytes=view.image_bytes, blocks_verified=view.block_count, image_sha256=complete.hexdigest(),
              volume_uuid=str(expected_uuid).upper(), generation=view.generation,
              source_compressed_sha256=digest.hexdigest(), source_format='UDIF' if spec['udif'] else 'raw',
              host_bus_protocol=host_protocol, host_media_writable=False,
              trusted_key_sha256=record['trusted_key_sha256'], actual_sample_indices=indices,
              actual_sample_lengths=lengths, real_c_signature_and_block_verification=True,
              original_image_modified=False, host_only=True, boot_root_authenticated=False,
              qemu_tested=False, hardware_tested=False)
report_path.write_text(json.dumps(report, indent=2) + '\n')
print(f'PASS: original {args.component} signature and every', view.block_count, 'block verified by real C/RSA; no expanded image')
