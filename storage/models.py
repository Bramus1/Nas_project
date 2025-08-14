from django.db import models
from django.conf import settings
from django.db import models
import uuid
from django.conf import settings
from django.db import models

class PublicKey(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    key_type = models.CharField(max_length=8, choices=[('ECDH','ECDH'),('ECDSA','ECDSA')])
    jwk = models.JSONField()              # PUBLIC JWK only (no private key!)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'key_type')  # one ECDH + one ECDSA per user

class Contact(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='contacts_owner')
    target = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='contacts_target')
    status = models.CharField(max_length=16, choices=[('pending','pending'),('accepted','accepted'),('denied','denied')])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('owner', 'target')



def oid():
    return uuid.uuid4().hex  # opaque id to avoid IDOR

class Directory(models.Model):
    oid       = models.CharField(max_length=64, default=oid, unique=True)
    owner     = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    parent    = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE)
    enc_name  = models.BinaryField()     # AES-GCM ciphertext of the directory name
    name_iv   = models.BinaryField()     # IV used to encrypt the name
    created_at= models.DateTimeField(auto_now_add=True)
    updated_at= models.DateTimeField(auto_now=True)

class FileBlob(models.Model):
    oid        = models.CharField(max_length=64, default=oid, unique=True)
    owner      = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    directory  = models.ForeignKey(Directory, null=True, blank=True, on_delete=models.SET_NULL)
    enc_name   = models.BinaryField()    # AES-GCM ciphertext of the file name
    name_iv    = models.BinaryField()
    size_bytes = models.BigIntegerField()
    chunk_count= models.IntegerField(default=0)
    upload_token = models.CharField(max_length=64, null=True, blank=True)  # temporary token for chunk upload
    created_at = models.DateTimeField(auto_now_add=True)
  # A2: whole-file manifest (Merkle root over ciphertext chunks)
    manifest_algo = models.CharField(max_length=16, default='sha256')
    manifest_root = models.BinaryField(null=True, blank=True)  # 32 bytes for sha256
    manifest_version = models.IntegerField(default=1)
    manifest_sig = models.BinaryField(null=True, blank=True)  # (optional) if you later sign manifests

class FileChunk(models.Model):
    file      = models.ForeignKey(FileBlob, on_delete=models.CASCADE)
    index     = models.IntegerField()
    iv        = models.BinaryField()     # AES-GCM IV for this chunk
    ciphertext= models.BinaryField()     # encrypted bytes for this chunk
    length    = models.IntegerField()

    class Meta:
        unique_together = ('file', 'index')
        ordering = ['index']


from django.conf import settings
from django.db import models

class WrappedKey(models.Model):
    """
    Per-recipient wrapped file key (read-only share).
    The wrapping is done CLIENT-SIDE with ECDH+HKDF → AES-GCM.
    """
    file = models.ForeignKey(FileBlob, on_delete=models.CASCADE, related_name='wrapped_keys')
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wrapped_keys')
    # base64url strings stored as bytes (we'll base64 encode/decode in views)
    wrap_iv = models.BinaryField()       # 12B IV used for AES-GCM wrapping
    wrapped_key = models.BinaryField()   # ciphertext of the raw AES file key
    permission = models.CharField(max_length=8, default='read')  # future: 'read','write'
    created_at = models.DateTimeField(auto_now_add=True)

    # NEW: snapshot of the owner’s ECDH public JWK at share time
    owner_pub_jwk = models.JSONField(null=True, blank=True)  # Django 5 JSONField

    # (Optional) If your DB doesn’t support JSON, use TextField instead:
    # owner_pub_jwk = models.TextField(null=True, blank=True)

    class Meta:
        unique_together = ('file', 'recipient')


