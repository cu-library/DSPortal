import os
import time
import requests
import mimetypes
import json
import traceback
from requests_toolbelt.multipart import encoder

# API_BASE & Base URL supplied as an argument through click to speicfy if were on Dev or Live
API_BASE = "https://carleton-dev.scholaris.ca/server/api"
DSPACE_BASE_URL = "https://carleton-dev.scholaris.ca"

OG_BITSTREAM_PAYLOAD = { 
                "name": "", 
                "description": "",
                "type": "bitstream",
                "bundleName": "ORIGINAL" 
                }

LICENSE_BITSTREAM_PAYLOAD = {
                "name": "", 
                "description": "",
                "type": "license",
                "bundleName": "LICENSE" 
                }

class DSpaceSession(requests.Session):
    def __init__(self, api_base, debug=False):
        super().__init__()
        self.api_base = api_base
        self.auth_token = None
        self.last_auth_time = None
        self.csrf_token = None
        self.debug = debug
        self.fetch_initial_csrf_token()

    def log_error(self, context, exc=None, response=None, extra=None):
        print(f"\n[ERROR] {context}")
        if exc:
            print(f"  Exception: {str(exc)}")
            traceback.print_exc()
        if response is not None:
            print(f"  Status Code: {response.status_code}")
            print(f"  Response Body: {response.text}")
        if extra:
            print(f"  Extra Info: {extra}")
        print()

    def fetch_initial_csrf_token(self):
        try:
            response = super().get(f"{self.api_base}/security/csrf")
            response.raise_for_status()
            self.headers.update(response)
        except Exception as e:
            self.log_error("Failed to fetch intial CSRF token", e)

    def authenticate(self, user, password):
        login_payload = {"user": user, "password": password}
        try:
            response = self.post(f"{self.api_base}/authn/login", data=login_payload)
            response.raise_for_status()
            self.update_csrf_token(response)

            self.auth_token = response.headers.get("Authorization")
            if self.auth_token:
                self.headers.update({"Authorization": self.auth_token})
                self.last_auth_time = time.time()
            else:
                self.log_error("Missing Authorization token in response headers")
        except requests.exceptions.RequestException as e:
            self.log_error("Authentication request failed", e)
        except Exception as e:
            self.log_error("Unexpected error during authentication", e)

    def refresh_csrf_token(self):
        response = super().get(f"{self.api_base}/security/csrf")
        response.raise_for_status()
        self.update_csrf_token(response)

    def ensure_auth_valid(self, user, password):
        if self.auth_token and (time.time() - self.last_auth_time > 1800):
            self.authenticate(user, password)        

    def update_csrf_token(self, response):
        if "dspace-xsrf-token" in response.headers:
            self.csrf_token = response.headers["DSPACE-XSRF-TOKEN"]
            self.headers.update({"X-XSRF-TOKEN": self.csrf_token})

    def request(self, method, url, **kwargs):
        try:
            response = super().request(method, url, **kwargs)
            response.raise_for_status()
            self.update_csrf_token(response)
            return response

        except requests.exceptions.HTTPError as e:
            self.log_error("HTTP error during request", e, response, extra={
                "method": method,
                "url": url,
                "kwargs": kwargs
            })
            if self.debug:
                raise
        except requests.exceptions.RequestException as e:
            self.log_error("Request exception occurred", e, extra={
                "method": method,
                "url": url,
                "kwargs": kwargs
            })
            if self.debug:
                raise
        except Exception as e:
            self.log_error("Unexpected error in request", e, extra={
                "method": method,
                "url": url,
                "kwargs": kwargs
            })
            if self.debug:
                raise

        return None

    def safe_request(self, method, url, **kwargs):
        return self.request(method, url, **kwargs)
    

def item_creation(session, collection_id, metadata_payload):
    item_endpoint = f"{API_BASE}/core/items?owningCollection={collection_id}"
    response = session.safe_request("POST", item_endpoint, json=metadata_payload)
    response.raise_for_status()
    item_uuid = response.json()["uuid"]  
    item_handle = response.json()["handle"]
    return item_uuid, item_handle

def bundle_creations(session, item_uuid):
    
    bundle_endpoint = f"{API_BASE}/core/items/{item_uuid}/bundles"
    try:
        response = session.safe_request("POST", bundle_endpoint, json={"name":"ORIGINAL"})
        response.raise_for_status()
        og_bundle_id = response.json()["uuid"]
        
        response = session.safe_request("POST", bundle_endpoint, json={"name": "LICENSE"})
        response.raise_for_status()
        license_bundle_id = response.json()["uuid"]
        
        return og_bundle_id, license_bundle_id
    except requests.exceptions.RequestException as e:
        print(f"Error creating bundles: {e}")
        return None, None
    
def upload_licenses(session, license_bundle_uuid, license_dir):
    license_files = [
        ("license.txt", "Carleton University License"),
    ]

    license_endpoint = f"{API_BASE}/core/bundles/{license_bundle_uuid}/bitstreams"
    format_id = 2
    format_url = f"{API_BASE}/core/bitstreamformats/{format_id}"
    headers = {"Content-Type": "text/uri-list"}

    for filename, description in license_files:
        full_path = os.path.join(license_dir, filename)
        if os.path.isfile(full_path):
            with open(full_path, "rb") as file:
                try:
                    license_upload = {"file": (filename, file, "text/plain")}
                    response = session.safe_request("POST", license_endpoint, files=license_upload, data=LICENSE_BITSTREAM_PAYLOAD)
                    
                    if response:
                        license_uuid = response.json()["id"]
                        bitstream_endpoint = f"{API_BASE}/core/bitstreams/{license_uuid}/format"

                        try:
                            response = session.safe_request("PUT", bitstream_endpoint, headers=headers, data=format_url)
                            response.raise_for_status()
                        except requests.exceptions.RequestException as e:
                            print(f"[{description}] Failed to update MIME type: {e}")
                except Exception as e:
                    print(f"[{description}] Failed to upload license: {e}")
        else:
            print(f"[{description}] File not found: {full_path}")

def upload_files(session, package_data, og_bundle_uuid, file_path, metadata_payload):

    original_endpoint = f"{API_BASE}/core/bundles/{og_bundle_uuid}/bitstreams"

    for file_name in package_data.package_files:
        full_path = os.path.join(file_path, file_name)

        if not os.path.isfile(full_path):
            print(f"File not found: {full_path}, skipping")
            continue

        mime_type = mimetypes.guess_type(file_name)[0]
        
        with open(full_path, "rb") as file:

            if os.path.getsize(full_path) > 1048576000:

                multipart_data = {
                    'file': (file_name, file),
                    'OG_BITSTREAM_PAYLOAD': (None, json.dumps(metadata_payload), 'application/json')
                }
            
                e = encoder.MultipartEncoder(multipart_data)
                m = encoder.MultipartEncoderMonitor(e, lambda a: print(a.bytes_read, end='\r'))

                def gen():
                    a = m.read(16384)
                    while a:
                        yield a
                        a = m.read(16384)
                try:

                    response = session.safe_request("POST", original_endpoint, data=gen(), headers={"Content-Type": m.content_type})
                    response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    print(f"Error with multipart upload of {file_path}: {e}")
                    continue

            else:
                files = {"file": (file_name, file, mime_type)}
                try:
                    response = session.safe_request("POST", original_endpoint, files=files, data=metadata_payload)
                    response.raise_for_status()
                except requests.exceptions.RequestException as e:
                    print(f"Error uploading {file_path}: {e}")
                    continue
            print(f"Successfully uploaded: {file_path}") 


if __name__ == "__main__":  


    metadata_payload = {
        "name": "Example Payload Title",
        "metadata": [
            {
                "key": "dc.title",
                "value": "Test Item for DSPortal",
                "language": "en"
            },
            {
                "key": "dc.creator",
                "value": "Manfred Raffelsieper",
                "language": "en"
            },
            {
                "key": "dc.date.issued",
                "value": "2025-07-15"
            }
        ],
        "inArchive": True,
        "discoverable": True,
        "withdrawn": False,
        "type": "item"
    }


    session = DSpaceSession(API_BASE)
    item_uuid, item_handle = item_creation(session, collection_id, metadata_payload)
    bundle_creations(session, item_uuid)
    upload_files(session, file_path=None)