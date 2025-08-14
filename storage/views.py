from django.shortcuts import render

# Create your views here.
from django.contrib.auth import get_user_model
from .models import PublicKey, Contact
# storage/views.py
from .models import  WrappedKey
import  json, secrets
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseForbidden, Http404
from django.views.decorators.http import require_http_methods
from .models import Directory, FileBlob, FileChunk


User = get_user_model()

def _bad(msg, code=400):
    return JsonResponse({"ok": False, "error": msg}, status=code)

@login_required
@require_http_methods(["POST"])
def publish_keys(request):
    """
    Body: { "ecdsa": <PUBLIC JWK>, "ecdh": <PUBLIC JWK> }
    Upserts the caller's public keys.
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        ecdsa = body.get("ecdsa")
        ecdh  = body.get("ecdh")
        if not (ecdsa and ecdh):
            return _bad("missing ecdsa/ecdh JWKs")

        PublicKey.objects.update_or_create(
            user=request.user, key_type="ECDSA", defaults={"jwk": ecdsa}
        )
        PublicKey.objects.update_or_create(
            user=request.user, key_type="ECDH", defaults={"jwk": ecdh}
        )
        return JsonResponse({"ok": True})
    except Exception as e:
        return _bad(str(e))

@login_required
@require_http_methods(["GET"])
def get_public_keys(request, username):
    """
    Returns { ok, username, ecdsa, ecdh } if user exists.
    """
    try:
        u = User.objects.get(username=username)
    except User.DoesNotExist:
        return _bad("user not found", 404)

    res = {"ok": True, "username": username, "ecdsa": None, "ecdh": None}
    for pk in PublicKey.objects.filter(user=u):
        if pk.key_type == "ECDSA": res["ecdsa"] = pk.jwk
        if pk.key_type == "ECDH":  res["ecdh"]  = pk.jwk
    return JsonResponse(res)

@login_required
@require_http_methods(["POST"])
def contact_request(request):
    """
    Body: { "username": "<target>" }
    Creates/updates a 'pending' contact from request.user -> target.
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        uname = body.get("username")
        if not uname:
            return _bad("missing username")
        if uname == request.user.username:
            return _bad("cannot add yourself")

        try:
            target = User.objects.get(username=uname)
        except User.DoesNotExist:
            return _bad("user not found", 404)

        obj, created = Contact.objects.get_or_create(
            owner=request.user, target=target, defaults={"status": "pending"}
        )
        if not created and obj.status != "pending":
            obj.status = "pending"
            obj.save()

        return JsonResponse({"ok": True, "contact_id": obj.id, "status": obj.status})
    except Exception as e:
        return _bad(str(e))

@login_required
@require_http_methods(["GET"])
def contacts_list(request):
    """
    Lists contacts you created and requests sent to you.
    """
    mine = Contact.objects.filter(owner=request.user)
    to_me = Contact.objects.filter(target=request.user)

    def item(c):
        return {"id": c.id, "owner": c.owner.username, "target": c.target.username, "status": c.status}

    return JsonResponse({"ok": True,
                         "mine": [item(c) for c in mine],
                         "incoming": [item(c) for c in to_me]})

@login_required
@require_http_methods(["POST"])
def contact_accept(request):
    """
    Body: { "contact_id": <id> } — only the 'target' can accept.
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        cid = body.get("contact_id")
        if not cid:
            return _bad("missing contact_id")
        c = Contact.objects.get(id=cid)
        if c.target_id != request.user.id:
            return HttpResponseForbidden("only target can accept")
        c.status = "accepted"
        c.save()
        return JsonResponse({"ok": True})
    except Contact.DoesNotExist:
        return _bad("contact not found", 404)
    except Exception as e:
        return _bad(str(e))

@login_required
@require_http_methods(["POST"])
def contact_deny(request):
    """
    Body: { "contact_id": <id> } — only the 'target' can deny.
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        cid = body.get("contact_id")
        if not cid:
            return _bad("missing contact_id")
        c = Contact.objects.get(id=cid)
        if c.target_id != request.user.id:
            return HttpResponseForbidden("only target can deny")
        c.status = "denied"
        c.save()
        return JsonResponse({"ok": True})
    except Contact.DoesNotExist:
        return _bad("contact not found", 404)
    except Exception as e:
        return _bad(str(e))


# storage/views.py


def _bad(msg, code=400):
    return JsonResponse({"ok": False, "error": msg}, status=code)


import base64

def b64d(s):  # url-safe base64 decode to bytes (accepts missing padding)
    if isinstance(s, str):
        s = s.encode('ascii')
    # restore padding to a multiple of 4
    s += b'=' * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s)
    except Exception as e:
        # make the error visible in the HTTP response (easier to debug)
        raise ValueError(f'base64 decode error: {e}')

def b64e(b: bytes):  # bytes -> url-safe base64 str
    return base64.urlsafe_b64encode(b).decode('utf-8')

@login_required
@require_http_methods(["POST"])
def dir_create(request):
    """
    Body: { parent_oid?: str|null, enc_name: b64, name_iv: b64 }
    Creates a directory owned by the caller. Returns {oid}.
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        parent_oid = body.get("parent_oid")
        enc_name = body.get("enc_name")
        name_iv  = body.get("name_iv")
        if not (enc_name and name_iv):
            return _bad("missing enc_name/name_iv")

        parent = None
        if parent_oid:
            try:
                parent = Directory.objects.get(oid=parent_oid, owner=request.user)
            except Directory.DoesNotExist:
                return _bad("parent not found or not yours", 404)

        d = Directory.objects.create(
            owner=request.user,
            parent=parent,
            enc_name=b64d(enc_name),
            name_iv=b64d(name_iv),
        )
        return JsonResponse({"ok": True, "oid": d.oid})
    except Exception as e:
        return _bad(str(e))

@login_required
@require_http_methods(["GET"])
def dir_list(request):
    """
    Query: ?parent=<oid or empty for roots>
    Lists directories/files under a parent (owner-only for now).
    Returns: { dirs:[{oid,enc_name,name_iv}], files:[{oid,enc_name,name_iv,size_bytes,chunk_count}] }
    """
    parent_oid = request.GET.get("parent")
    if parent_oid:
        try:
            parent = Directory.objects.get(oid=parent_oid, owner=request.user)
        except Directory.DoesNotExist:
            return _bad("parent not found or not yours", 404)
        dirs = Directory.objects.filter(owner=request.user, parent=parent)
        files= FileBlob.objects.filter(owner=request.user, directory=parent)
    else:
        dirs = Directory.objects.filter(owner=request.user, parent__isnull=True)
        files= FileBlob.objects.filter(owner=request.user, directory__isnull=True)

    def d_item(d):
        return {"oid": d.oid, "enc_name": b64e(d.enc_name), "name_iv": b64e(d.name_iv)}
    def f_item(f):
        return {"oid": f.oid, "enc_name": b64e(f.enc_name), "name_iv": b64e(f.name_iv),
                "size_bytes": f.size_bytes, "chunk_count": f.chunk_count}

    return JsonResponse({"ok": True,
                         "dirs": [d_item(x) for x in dirs],
                         "files":[f_item(x) for x in files]})

@login_required
@require_http_methods(["POST"])
def file_init(request):
    """
    Body: { directory_oid?: str|null, enc_name: b64, name_iv: b64, size_bytes: int }
    Creates a file record and returns {file_oid, upload_token}.
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        directory_oid = body.get("directory_oid")
        enc_name = body.get("enc_name")
        name_iv  = body.get("name_iv")
        size     = int(body.get("size_bytes", 0))
        if not (enc_name and name_iv and size >= 0):
            return _bad("missing enc_name/name_iv/size_bytes")

        directory = None
        if directory_oid:
            try:
                directory = Directory.objects.get(oid=directory_oid, owner=request.user)
            except Directory.DoesNotExist:
                return _bad("directory not found or not yours", 404)

        token = secrets.token_urlsafe(32)
        fb = FileBlob.objects.create(
            owner=request.user, directory=directory, size_bytes=size,
            enc_name=b64d(enc_name), name_iv=b64d(name_iv), upload_token=token
        )
        return JsonResponse({"ok": True, "file_oid": fb.oid, "upload_token": token})
    except Exception as e:
        return _bad(str(e))

@login_required
@require_http_methods(["POST"])
def file_chunk(request):
    """
    Body: { file_oid: str, upload_token: str, index: int, iv: b64, ciphertext: b64, length: int }
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        file_oid = body.get("file_oid")
        token    = body.get("upload_token")
        index    = int(body.get("index"))
        iv       = body.get("iv")
        ct       = body.get("ciphertext")
        length   = int(body.get("length"))

        if not all([file_oid, token, iv, ct]):
            return _bad("missing fields")

        try:
            fb = FileBlob.objects.get(oid=file_oid, owner=request.user)
        except FileBlob.DoesNotExist:
            return _bad("file not found or not yours", 404)

        if token != fb.upload_token:
            return _bad("bad upload token", 403)

        FileChunk.objects.create(
            file=fb, index=index, iv=b64d(iv), ciphertext=b64d(ct), length=length
        )
        return JsonResponse({"ok": True})
    except Exception as e:
        return _bad(str(e))

@login_required
@require_http_methods(["POST"])
def file_finalize(request):
    """
    Body: { file_oid: str, upload_token: str, chunk_count: int,
            manifest?: { algo:'sha256', n:int, root_b64:str, version:int, sig_b64?:str } }
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        file_oid = body.get("file_oid")
        token    = body.get("upload_token")
        chunk_count = int(body.get("chunk_count", 0))
        manifest = body.get("manifest")

        try:
            fb = FileBlob.objects.get(oid=file_oid, owner=request.user)
        except FileBlob.DoesNotExist:
            return _bad("file not found or not yours", 404)

        if token != fb.upload_token:
            return _bad("bad upload token", 403)

        fb.chunk_count = chunk_count
          # A2: persist manifest if provided
        if manifest:
            algo = manifest.get("algo", "sha256")
            if algo != "sha256":
                return _bad("unsupported manifest algo", 400)
            n=int(manifest.get("n", -1))
            if n!= chunk_count:
                return _bad("manifest chunk count mismatch", 400)
            root_b64 = manifest.get("root_b64")
            if not root_b64:
                return _bad("missing manifest root_b64", 400)
            root= b64d(root_b64)
            if len(root) != 32:  # sha256 root is always 32 bytes
                return _bad("invalid manifest root length", 400)
            fb.manifest_algo = algo
            fb.manifest_root = root
            fb.manifest_version = manifest.get("version", 1)
            sig_b64 = manifest.get("sig_b64")
            if sig_b64:
                fb.manifest_sig = b64d(sig_b64)

        fb.upload_token = None  # invalidate token
        fb.save()
        return JsonResponse({"ok": True})
    except Exception as e:
        return _bad(str(e))

def _has_read_access(user, fb: FileBlob):
    if fb.owner_id == user.id:
        return True
    return WrappedKey.objects.filter(file=fb, recipient=user, permission='read').exists()

@login_required
@require_http_methods(["GET"])
def file_meta(request, oid):
    try:
        fb = FileBlob.objects.get(oid=oid)
    except FileBlob.DoesNotExist:
        return JsonResponse({"ok": False, "error": "file not found"}, status=404)
    if not _has_read_access(request.user, fb):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)
    return JsonResponse({
        "ok": True,
        "size_bytes": fb.size_bytes,
        "chunk_count": fb.chunk_count,
        "enc_name": b64e(fb.enc_name),
        "name_iv": b64e(fb.name_iv),
        "manifest_algo": fb.manifest_algo,
        "manifest_version": fb.manifest_version,
        "manifest_root": b64e(fb.manifest_root) if fb.manifest_root else None,
        "manifest_sig": b64e(fb.manifest_sig) if fb.manifest_sig else None,
    })

@login_required
@require_http_methods(["GET"])
def file_chunk_get(request, oid, index: int):
    try:
        fb = FileBlob.objects.get(oid=oid)
    except FileBlob.DoesNotExist:
        return JsonResponse({"ok": False, "error": "not found"}, status=404)
    if not _has_read_access(request.user, fb):
        return JsonResponse({"ok": False, "error": "forbidden"}, status=403)
    try:
        ch = FileChunk.objects.get(file=fb, index=index)
    except FileChunk.DoesNotExist:
        return JsonResponse({"ok": False, "error": "chunk not found"}, status=404)
    return JsonResponse({
        "ok": True,
        "iv": b64e(ch.iv),
        "ciphertext": b64e(ch.ciphertext),
        "length": ch.length,
    })
@login_required
@require_http_methods(["POST"])
def share_create(request):
    """
    Owner posts a recipient-wrapped file key.
      Body: { file_oid, username, wrap_iv: b64, wrapped_key: b64 }
    Validates: owner == request.user and (optional) contact exists/accepted.
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        owner_pub_jwk = body.get("owner_pub_jwk")  # may be dict (JSON) or string
        file_oid = body.get("file_oid")
        uname    = body.get("username")
        wrap_iv  = body.get("wrap_iv")
        wkey     = body.get("wrapped_key")
        if not all([file_oid, uname, wrap_iv, wkey]):
            return _bad("missing fields")

        try:
            fb = FileBlob.objects.get(oid=file_oid, owner=request.user)
        except FileBlob.DoesNotExist:
            return _bad("file not found or not yours", 404)

        try:
            recipient = User.objects.get(username=uname)
        except User.DoesNotExist:
            return _bad("recipient not found", 404)

        # (optional) enforce relationship: must be accepted contacts both ways
        # if not Contact.objects.filter(owner=request.user, target=recipient, status='accepted').exists():
        #     return _bad("recipient is not an accepted contact")

        obj, _ = WrappedKey.objects.update_or_create(
            file=fb, recipient=recipient,
            defaults={"wrap_iv": b64d(wrap_iv), "wrapped_key": b64d(wkey), "permission": "read",   "owner_pub_jwk": owner_pub_jwk,}
        )
        return JsonResponse({"ok": True})
    except Exception as e:
        return _bad(str(e))

@login_required
@require_http_methods(["GET"])
def share_list_for_me(request):
    """
    List files shared TO the current user.
    Returns minimal info to render and download.
    """
    items = WrappedKey.objects.filter(recipient=request.user).select_related('file', 'file__owner', 'file__directory')
    def row(w):
        f = w.file
        return {
            "file_oid": f.oid,
            "owner": f.owner.username,
            "enc_name": b64e(f.enc_name),
            "name_iv": b64e(f.name_iv),
            "size_bytes": f.size_bytes,
            "chunk_count": f.chunk_count,
        }
    return JsonResponse({"ok": True, "items": [row(w) for w in items]})

@login_required
@require_http_methods(["GET"])
def share_my_wrapped_key(request, file_oid):
    """
    Return this user's wrapped key for a given file, plus owner info.
    """
    try:
        w = WrappedKey.objects.select_related('file','file__owner').get(
            file__oid=file_oid, recipient=request.user
        )
    except WrappedKey.DoesNotExist:
        return _bad("no wrapped key", 404)

    return JsonResponse({
        "ok": True,
        "owner": w.file.owner.username,
        "wrap_iv": b64e(w.wrap_iv),
        "wrapped_key": b64e(w.wrapped_key),
        "permission": w.permission,
        "owner_pub_jwk": w.owner_pub_jwk,
    })

# at top of file (if not present already)
import os
from django.db import transaction

@login_required
@require_http_methods(["POST"])
def file_shred_delete(request):
    """
    Owner-only: overwrite chunk ciphertext with random bytes, then delete file.
    Body: { "file_oid": "<oid>" }
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        file_oid = body.get("file_oid")
        if not file_oid:
            return JsonResponse({"ok": False, "error": "missing file_oid"}, status=400)

        with transaction.atomic():
            try:
                fb = FileBlob.objects.select_for_update().get(oid=file_oid, owner=request.user)
            except FileBlob.DoesNotExist:
                return JsonResponse({"ok": False, "error": "file not found or not yours"}, status=404)

            # Overwrite all chunks with random data of equal length + fresh IV
            chunks = list(FileChunk.objects.filter(file=fb).only("id", "ciphertext", "length"))
            for ch in chunks:
                old_len = len(ch.ciphertext)
                rnd = os.urandom(old_len)
                iv = os.urandom(12)
                ch.ciphertext = rnd
                ch.iv = iv
                ch.save(update_fields=["ciphertext", "iv"])

            # Remove any wrapped keys (shares)
            WrappedKey.objects.filter(file=fb).delete()

            # Delete chunks then the file row
            FileChunk.objects.filter(file=fb).delete()
            fb.delete()

        return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)

from django.db import transaction
import os

@login_required
@require_http_methods(["POST"])
def share_remove_for_me(request):
    """
    Recipient-only removal: remove my WrappedKey for a shared file.
    Body: { "file_oid": "<oid>" }
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        file_oid = body.get("file_oid")
        if not file_oid:
            return JsonResponse({"ok": False, "error": "missing file_oid"}, status=400)

        try:
            fb = FileBlob.objects.get(oid=file_oid)
        except FileBlob.DoesNotExist:
            return JsonResponse({"ok": False, "error": "file not found"}, status=404)

        # Delete only THIS user's wrapped key; owner copy untouched
        deleted, _ = WrappedKey.objects.filter(file=fb, recipient=request.user).delete()
        if deleted == 0:
            return JsonResponse({"ok": False, "error": "no share existed for you"}, status=404)
        return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)


@login_required
@require_http_methods(["POST"])
def dir_shred_delete(request):
    """
    Owner-only: recursively shred (randomize) all file chunks under a directory,
    remove all WrappedKeys for those files, then delete files and directories.
    Body: { "dir_oid": "<oid>" }
    """
    try:
        body = json.loads(request.body.decode("utf-8"))
        dir_oid = body.get("dir_oid")
        if not dir_oid:
            return JsonResponse({"ok": False, "error": "missing dir_oid"}, status=400)

        try:
            root = Directory.objects.get(oid=dir_oid, owner=request.user)
        except Directory.DoesNotExist:
            return JsonResponse({"ok": False, "error": "directory not found or not yours"}, status=404)

        # Collect all descendant directories (BFS)
        to_visit = [root]
        all_dirs = []
        while to_visit:
            d = to_visit.pop()
            all_dirs.append(d)
            children = Directory.objects.filter(parent=d, owner=request.user)
            to_visit.extend(list(children))

        # Collect all files in these directories
        all_dir_ids = [d.id for d in all_dirs]
        files = list(FileBlob.objects.filter(directory_id__in=all_dir_ids, owner=request.user))

        with transaction.atomic():
            # Shred every file's chunks, delete shares, then delete chunks & files
            for fb in files:
                chunks = list(FileChunk.objects.filter(file=fb).only("id", "ciphertext"))
                for ch in chunks:
                    rnd = os.urandom(len(ch.ciphertext))
                    iv = os.urandom(12)
                    ch.ciphertext = rnd
                    ch.iv = iv
                    ch.save(update_fields=["ciphertext", "iv"])
                WrappedKey.objects.filter(file=fb).delete()
                FileChunk.objects.filter(file=fb).delete()
                fb.delete()

            # Finally delete directories (deepest first is safest)
            for d in sorted(all_dirs, key=lambda x: x.id, reverse=True):
                d.delete()

        return JsonResponse({"ok": True})
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)}, status=400)
