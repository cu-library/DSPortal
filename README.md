## DSPortal

DSPortal is a Python-based utility that simplifies ingesting content into a [DSpace 7/8](https://wiki.lyrasis.org/display/DSDOC7x/REST+API) repository via the REST API. It handles authentication, CSRF protection, 

Designed for repeatable and scriptable metadata and file ingestion workflows.

Example methods for item creation, bundle setup, and bitstream uploads.

---

### Features

* Authenticated REST session with CSRF & token handling
* Easy integration with external metadata extraction tools

---

### Requirements

* Python 3.8+
* `requests`
* Access to a DSpace 7/8 instance with REST API enabled

---

### Example Usage

#### 1. Authenticate & Create Session

```python
session = DSpaceSession(api_base="https://carleton-dev.scholaris.ca/server/api")
session.authenticate(user="dspace_admin", password="dspace_password")
```

#### 2. Create a New Item

```python
collection_id = "uuid-of-target-collection"

metadata_payload = {
    "name": "Title of Work",
    "metadata": "Insert structured metadata here",
    "inArchive": True,
    "discoverable": True,
    "withdrawn": False,
    "type": "item"
}

item_uuid, item_handle = item_creation(session, collection_id, metadata_payload)
```

#### 3. Create Bundles for the Item

```python
og_bundle_id, license_bundle_id = bundle_creations(session, item_uuid)
```

#### 4. Upload License File

```python
upload_licenses(session, license_bundle_id, license_dir="/path/to/licenses")
```

#### 5. Upload Original Files
```
file = path/to/files
upload_files(session, package_data, og_bundle_id, file, OG_BITSTREAM_PAYLOAD)
```

---

### Developer Notes

* **Token Expiration**: Sessions expire after \~30 mins. Call `ensure_auth_valid(user, password)` to auto-refresh.
* **CSRF Handling**: Automatically managed after login and per request.
* **Error Handling**: Logs basic failures; expand logging if needed.
* **Large Files**: Files >1GB are uploaded with `MultipartEncoder` (commented out in this sample; plug in your encoder module as needed).

---

### Furture Features

* CLI Wrapper via `click`
* Retry logic for flaky uploads
* Logging system integration
* Better metadata schema validation before submit

---

