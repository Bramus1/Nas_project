from django.urls import path
from . import views

urlpatterns = [
    path('keys/publish', views.publish_keys, name='publish_keys'),
    path('keys/of/<str:username>', views.get_public_keys, name='get_public_keys'),

    path('contacts/request', views.contact_request, name='contact_request'),
    path('contacts/list', views.contacts_list, name='contacts_list'),
    path('contacts/accept', views.contact_accept, name='contact_accept'),
    path('contacts/deny', views.contact_deny, name='contact_deny'),

    # NEW: directories + files (owner-only for now)
    path('dir/create', views.dir_create, name='dir_create'),
    path('dir/list', views.dir_list, name='dir_list'),
    path('file/init', views.file_init, name='file_init'),
    path('file/chunk', views.file_chunk, name='file_chunk'),
    path('file/finalize', views.file_finalize, name='file_finalize'),
    path('file/meta/<str:oid>', views.file_meta, name='file_meta'),
    path('file/chunk/<str:oid>/<int:index>', views.file_chunk_get, name='file_chunk_get'),
# sharing
path('share/create', views.share_create, name='share_create'),
path('share/list', views.share_list_for_me, name='share_list_for_me'),
path('share/mykey/<str:file_oid>', views.share_my_wrapped_key, name='share_my_wrapped_key'),
# file ops
path('file/delete', views.file_shred_delete, name='file_shred_delete'),
# delete / revoke
path('share/remove', views.share_remove_for_me, name='share_remove_for_me'),  # recipient self-unshare
path('dir/delete', views.dir_shred_delete, name='dir_shred_delete'),         # owner recursive shred+delete

]
