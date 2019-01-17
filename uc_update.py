from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from zipfile import ZipFile

import os
import urllib
import urlparse
import sys
import codecs
import base64
import json
import hashlib
import yaml

def main(argv):
  """Main program"""
  config = load_config(argv[1])
  update_center = load_update_center(config['update_center'])
  plugin_locations = update_local_repository(update_center, config['local_repository'])
  modify_update_center(update_center, config['local_repository'])
  save_update_center(update_center, config['local_repository'])

def load_update_center(uc_config):
  """
  Load update center contents from given url
  """
  update_center = json.load(urllib.urlopen(uc_config['url']))
  signature = remove_signature(update_center)
  c_update_center = canonicalize(update_center)

  verify_update_center_digest(
    c_update_center, hashlib.sha512, signature['correct_digest512'])

  verify_update_center_signature(
    c_update_center, pick_certificate(decode_certificates(signature['certificates']), load_certificate(uc_config['ca_cert_path'])),
    hashes.SHA512(), signature['correct_signature512'])

  return update_center

def modify_update_center(update_center, local_repository):
  """Modify update center for storing as local repository"""
  modify_update_center_connection_check_url(update_center, local_repository['url'])
  modify_update_center_core_url(update_center, local_repository['url'])
  modify_update_center_plugin_urls(update_center, local_repository['url'])
  add_update_center_signature(update_center, local_repository['signing']['cert_path'], local_repository['signing']['key_path'])

def modify_update_center_connection_check_url(update_center, repository_url):
  """Set connection check url"""
  update_center['connectionCheckUrl'] = repository_url

def modify_update_center_core_url(update_center, repository_url):
  """Set core url"""
  update_center['core']['url'] = repository_url + get_url_path(update_center['core']['url'])

def modify_update_center_plugin_urls(update_center, repository_url):
  """Modify urls to point to local repository"""
  for plugin in update_center['plugins'].values():
    plugin['url'] = repository_url + get_url_path(plugin['url'])

def save_update_center(update_center, local_repository):
  """Save update-center.json to repository path"""
  with open(os.path.join(local_repository['path'], 'update-center.json'), 'wb') as f:
    json.dump(update_center, f)

def add_update_center_signature(update_center, certificate_path, private_key_path):
  """Sign update center"""  
  c_update_center = canonicalize(update_center)
  # We do not provide backwards compatiblity for old jenkins instances...
  # So some keys are left undefined
  signature = {
  'certificates': encode_certificates([load_certificate(certificate_path)]),
  'correct_digest512': hash_update_center(c_update_center, hashlib.sha512),
  'correct_signature512': sign_update_center(c_update_center, load_private_key(private_key_path), hashes.SHA512())
  }
  update_center.update({"signature": signature})

def remove_signature(update_center):
  """Remove signature from update center"""
  # This dictionary is huge, so we do not clone it
  return update_center.pop('signature')

def load_config(src):
  """Load configuration from yaml file"""
  return yaml.load(urllib.urlopen(src))

def canonicalize(input):
  """Return update center contents as canonicalized json"""
  # Sort by keys, remove spaces and encode as utf-8 
  return json.dumps(input, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

def hash_update_center(c_update_center, hash_algorithm):
  """Calculate update center's digest and return it as hexencoded"""
  return hash_algorithm(c_update_center).hexdigest()

def verify_update_center_digest(c_update_center, hash_algorithm, correct_digest):
  """Verify update center content using a hash"""
  # This is not a security feature (hash is not signed)
  # To be honest, I have no clue what is the purpose of this
  if hash_update_center(c_update_center, hash_algorithm) != correct_digest:
    raise ValueError('Digest does not match')

def sign_update_center(c_update_center, private_key, hash_algorithm):
  """Calculate signature for update center"""
  return ''.join('{:02x}'.format(x)
    for x in bytearray(private_key.sign(
      c_update_center,
      padding.PKCS1v15(),
      hash_algorithm)))

def load_private_key(private_key_path):
  """Load pem encoded private key"""
  with open(private_key_path, 'r') as f:
    return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_certificate(certificate_path):
  """Load pem encoded x509 certificate"""
  with open(certificate_path, 'r') as f:
    return x509.load_pem_x509_certificate(f.read(), default_backend())

def encode_certificates(certificates):
  """Encode multiple x509 certificates as base64 encoded der"""
  return [
    base64.b64encode(
      certificate.public_bytes(encoding = serialization.Encoding.DER))
    for certificate in certificates
  ]

def decode_certificates(der_encoded_certs):
  """Decode multiple base64 and der encoded x509 certifcates"""
  return [
    x509.load_der_x509_certificate(
      base64.b64decode(der_encoded_cert), default_backend())
    for der_encoded_cert in der_encoded_certs
  ]

def pick_certificate(certificates, ca):
  """Pick certificate signed with ca. There is likely to be one"""
  for certificate in certificates:
    try:
      ca.public_key().verify(
          certificate.signature,
          certificate.tbs_certificate_bytes,
          padding.PKCS1v15(),
          certificate.signature_hash_algorithm)
      return certificate
    except:
      pass
  raise ValueError('Could not locate trusted certificate. Check your ca configuration')

def verify_update_center_signature(c_update_center, certificate, hash_algorithm, correct_signature):
  """Verify update center's signature"""
  # This is a security feature, but this check is far from perfect (no crls etc..)
  # If you know a better way, please send a pull request :-)
  certificate.public_key().verify(
    bytes(bytearray.fromhex(correct_signature)),
    c_update_center,
    padding.PKCS1v15(),
    hash_algorithm
  )

def update_local_repository(update_center, local_repository):
  """Update local repository"""
  update_local_repository_core(update_center, local_repository)
  update_local_repository_plugins(update_center, local_repository, local_repository['plugins'])

def update_local_repository_core(update_center, local_repository):
  """Update jenkins core in local repository"""
  if local_repository['core']:
    download_item(update_center['core']['url'],
      translate_to_repository_path(update_center['core']['url'], local_repository['path']),
      update_center['core']['sha256'])

def update_local_repository_plugins(update_center, local_repository, requested_plugins, known_plugins = set()):
  """Update plugins in local repository"""
  # Unfortunately Jenkins update site's dependency management information is more or less broken
  # ... this is why we need to check dependencies from MANIFEST.MF as well. Lame...
  #
  for requested_plugin in local_repository['plugins']:
    for required_plugin in resolve_plugin(update_center, requested_plugin):
      plugin_id = '%s:%s' % (required_plugin['name'], required_plugin['version'])
      if not plugin_id in known_plugins:
        known_plugins.add(plugin_id)
        plugin_path = translate_to_repository_path(required_plugin['url'], local_repository['path'])
        download_item(required_plugin['url'],
          plugin_path,
          required_plugin['sha256'])
        with ZipFile(plugin_path) as hpi:
          update_local_repository_plugins(update_center, local_repository, get_manifest_dependencies(hpi), known_plugins)

def resolve_plugin(update_center, plugin):
  """Get plugin's details by it's name from update center"""
  uc_plugin = update_center['plugins'][plugin['name']]
  # Dependencies first
  return join(resolve_plugin(update_center, dependency) for dependency in uc_plugin.get('dependencies', [])) + [uc_plugin]

def get_manifest_dependencies(hpi):
  """Extract dependencies from plugin's manifest"""
  dep_lines = []
  with hpi.open('META-INF/MANIFEST.MF') as manifest:
    for line in manifest:
      if dep_lines and line.startswith(' '):
        dep_lines += [line[1:].rstrip('\r\n')]
      elif dep_lines:
        break
      elif line.startswith('Plugin-Dependencies: '):
        dep_lines += [line[21:].rstrip('\r\n')]
  return [{'name': p[0], 'version': p[1]} for p in [d.split(':') for d in ''.join(dep_lines).split(',')]] if dep_lines else []

def translate_to_repository_path(url, repository_path):
  """Translate url to a path in local repository"""
  return os.path.join(repository_path, get_url_path(url)[1:])

def get_url_path(url):
  """Return path fragment of url"""
  return urlparse.urlparse(url).path

def verify_item_checksum(hpi_path, checksum):
  """Verify that file is valid using a checksum"""
  h = hashlib.sha256()
  with open(hpi_path, 'rb') as f:
    buf = f.read(4096)
    while len(buf) > 0:
      h.update(buf)
      buf = f.read(4096)
  hpi_checksum = base64.b64encode(h.digest())
  if hpi_checksum != checksum:
    raise ValueError('Checksum from %s was %s, expected %s' % (hpi_path, hpi_checksum, checksum))

def download_item(hpi_url, hpi_path, checksum):
  """Download item to local repository, if it does not exist"""
  if not os.path.exists(hpi_path):
    hpi_path_new = hpi_path + '.new'
    hpi_dir = os.path.dirname(hpi_path)
    if not os.path.exists(hpi_dir):
      os.makedirs(hpi_dir)
    urllib.urlretrieve(hpi_url, hpi_path_new)
    verify_item_checksum(hpi_path_new, checksum)
    os.rename(hpi_path_new, hpi_path)

def join(lists):
  """Merge contents of multiple lists"""
  return [i for l in lists for i in l]

if __name__ == "__main__":
  main(sys.argv)
