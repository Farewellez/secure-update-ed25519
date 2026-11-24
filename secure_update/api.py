"""API distribusi update. Tidak ada signing key di server!"""
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from .repository import available_versions


def create_app(repo: Path) -> FastAPI:
    app = FastAPI(title="Secure Software Update - Demo", version="0.1.0")

    @app.get("/health")
    def health():
        return {"status": "ok", "releases": len(available_versions(repo))}

    def manifest_for(version: int) -> dict:
        if version < 1:
            raise HTTPException(status_code=404, detail="Version not found")
        path = repo / str(version) / "manifest.json"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Version not found")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise HTTPException(status_code=500, detail="Repository metadata corrupted")

    @app.get("/updates/latest")
    def latest():
        versions = available_versions(repo)
        if not versions:
            raise HTTPException(status_code=404, detail="No releases")
        return manifest_for(versions[-1])

    @app.get("/updates/{version}")
    def get_version(version: int):
        return manifest_for(version)

    @app.get("/packages/{version}")
    def get_package(version: int):
        if version < 1:
            raise HTTPException(status_code=404, detail="Version not found")
        path = repo / str(version) / "package.bin"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Version not found")
        return FileResponse(path, media_type="application/octet-stream", filename=f"cielapp-v{version}.bin")

    return app


app = create_app(Path(os.environ.get("UPDATE_REPO", "work/releases")))
