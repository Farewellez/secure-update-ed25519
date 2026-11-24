import httpx
import pytest
from fastapi.testclient import TestClient

from secure_update.api import create_app
from secure_update.crypto import create_key_pair
from secure_update.repository import publish_release


@pytest.fixture
def sandbox(tmp_path):
    keys = tmp_path / "keys"
    private, public = keys / "private.pem", keys / "public.pem"
    create_key_pair(private, public)
    repo = tmp_path / "repo"
    appfile1, appfile2 = tmp_path / "v1.bin", tmp_path / "v2.bin"
    appfile1.write_bytes(b"legitimate old version")
    appfile2.write_bytes(b"legitimate NEW version")
    publish_release(repo, appfile1, 1, private)
    publish_release(repo, appfile2, 2, private)
    api = TestClient(create_app(repo))

    def make_http(override=None):
        def handler(request):
            path = request.url.raw_path.decode("ascii").split("?", 1)[0]
            if override:
                custom = override(path, request)
                if custom is not None:
                    return custom
            resp = api.request(request.method, path)
            return httpx.Response(resp.status_code, content=resp.content,
                                  headers={"content-type": resp.headers.get("content-type", "application/json")})
        return httpx.Client(transport=httpx.MockTransport(handler))

    return {
        "private": private, "public": public, "repo": repo, "api": api,
        "tmp": tmp_path, "make_http": make_http,
    }
