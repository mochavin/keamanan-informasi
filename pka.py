import threading
import time
from rsa import generate_rsa_keys

class PublicKeyAuthority:
  def __init__(self):
    self.key_pairs = {} 
    self.lock = threading.Lock()

  def generate_key_pair(self, user_id):
    with self.lock:
      public_key, private_key = generate_rsa_keys()
      self.key_pairs[user_id] = (public_key, private_key)
      return public_key

  def get_public_key(self, user_id, timestamp):
    return self.key_pairs.get(user_id, (None, None))[0]

  def get_private_key(self, user_id):
    return self.key_pairs.get(user_id, (None, None))[1]
  
pka = PublicKeyAuthority()
