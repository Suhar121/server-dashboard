import os
import re
import shutil
import tempfile
import subprocess
from fastapi import APIRouter, HTTPException, Depends, Query, File, UploadFile, Form
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask
from pydantic import BaseModel
import config
import database
from routers.auth import require_role

router = APIRouter(prefix="/files", tags=["files"])

class FileReadRequest(BaseModel):
    path: str

class FileWriteRequest(BaseModel):
    path: str
    content: str

class FileDeleteRequest(BaseModel):
    path: str

class CreateDirectoryRequest(BaseModel):
    path: str

class GitCloneRequest(BaseModel):
    path: str
    repo_url: str
    folder_name: str | None = None

class FilePermissionsRequest(BaseModel):
    path: str
    permissions: str


def is_safe_path(path: str) -> bool:
    try:
        abs_path = os.path.abspath(path)
        forbidden_paths = ["/etc/shadow", "/etc/passwd", "/root", "/proc", "/sys"]
        for forbidden in forbidden_paths:
            if abs_path.startswith(forbidden):
                return False
        return True
    except Exception:
        return False


def get_file_info(path: str):
    try:
        stat_info = os.stat(path)
        return {
            "name": os.path.basename(path),
            "path": path,
            "is_directory": os.path.isdir(path),
            "is_file": os.path.isfile(path),
            "size": stat_info.st_size,
            "modified": int(stat_info.st_mtime),
            "permissions": oct(stat_info.st_mode)[-3:],
            "readable": os.access(path, os.R_OK),
            "writable": os.access(path, os.W_OK),
        }
    except Exception:
        return None


def list_directory(path: str):
    try:
        if not os.path.isdir(path):
            return None

        items = []
        for item in sorted(os.listdir(path)):
            item_path = os.path.join(path, item)
            info = get_file_info(item_path)
            if info:
                items.append(info)

        return items
    except Exception:
        return None


def suggest_git_clone_folder_name(repo_url: str) -> str:
    cleaned = (repo_url or "").strip().rstrip("/")
    if not cleaned:
        return "repo-clone"

    tail = cleaned.split("/")[-1].strip()
    if tail.endswith(".git"):
        tail = tail[:-4]

    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", tail).strip(".-_")
    return sanitized or "repo-clone"


def validate_path(path: str):
    if not path:
        return
    if not re.match(r"^[a-zA-Z0-9\-_./\\: ~@]+$", path):
        raise HTTPException(status_code=400, detail="Invalid path characters.")


@router.get("/browse")
def browse_files(path: str | None = Query(None), user=Depends(require_role("admin"))):
    if not path:
        path = os.getcwd()

    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Path not found")

    if os.path.isfile(path):
        info = get_file_info(path)
        return {"type": "file", "info": info, "parent": os.path.dirname(path)}

    items = list_directory(path)
    if items is None:
        raise HTTPException(status_code=500, detail="Failed to read directory")

    parent = os.path.dirname(path) if path != "/" else None

    return {
        "type": "directory",
        "path": path,
        "parent": parent,
        "items": items
    }


@router.post("/read")
def read_file_endpoint(data: FileReadRequest, user=Depends(require_role("admin"))):
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(data.path):
        raise HTTPException(status_code=404, detail="File not found")

    if not os.path.isfile(data.path):
        raise HTTPException(status_code=400, detail="Path is not a file")

    try:
        with open(data.path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        database.log_audit(user["username"], "read_file", f"Read file: {data.path}")

        return {
            "path": data.path,
            "content": content,
            "size": len(content)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")


@router.post("/write")
def write_file_endpoint(data: FileWriteRequest, user=Depends(require_role("admin"))):
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    try:
        parent_dir = os.path.dirname(data.path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, mode=0o755, exist_ok=True)

        with open(data.path, "w", encoding="utf-8") as f:
            f.write(data.content)

        database.log_audit(user["username"], "write_file", f"Wrote file: {data.path}")

        return {"status": "success", "path": data.path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write file: {str(e)}")


@router.post("/delete")
def delete_file_endpoint(data: FileDeleteRequest, user=Depends(require_role("admin"))):
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(data.path):
        raise HTTPException(status_code=404, detail="Path not found")

    try:
        if os.path.isfile(data.path):
            os.remove(data.path)
            database.log_audit(user["username"], "delete_file", f"Deleted file: {data.path}")
        elif os.path.isdir(data.path):
            shutil.rmtree(data.path)
            database.log_audit(user["username"], "delete_directory", f"Deleted directory: {data.path}")

        return {"status": "deleted", "path": data.path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete: {str(e)}")


@router.post("/mkdir")
def create_directory_endpoint(data: CreateDirectoryRequest, user=Depends(require_role("admin"))):
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if os.path.exists(data.path):
        raise HTTPException(status_code=409, detail="Path already exists")

    try:
        os.makedirs(data.path, mode=0o755)
        database.log_audit(user["username"], "create_directory", f"Created directory: {data.path}")

        return {"status": "created", "path": data.path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create directory: {str(e)}")


@router.post("/git-clone")
def git_clone_repository(data: GitCloneRequest, user=Depends(require_role("admin"))):
    base_path = os.path.abspath((data.path or "").strip())
    repo_url = (data.repo_url or "").strip()
    folder_name = (data.folder_name or "").strip()

    if not base_path:
        raise HTTPException(status_code=400, detail="Target directory path is required")

    if not is_safe_path(base_path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(base_path) or not os.path.isdir(base_path):
        raise HTTPException(status_code=404, detail="Target directory not found")

    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required")

    if any(ch in repo_url for ch in ("\n", "\r", "\x00")):
        raise HTTPException(status_code=400, detail="Invalid repository URL")

    if repo_url.startswith("-"):
        raise HTTPException(status_code=400, detail="Invalid repository URL")

    if not folder_name:
        folder_name = suggest_git_clone_folder_name(repo_url)

    if not config.GIT_CLONE_FOLDER_PATTERN.match(folder_name):
        raise HTTPException(
            status_code=400,
            detail="Folder name must be 1-128 chars using letters, numbers, dot, dash, underscore",
        )

    target_path = os.path.abspath(os.path.join(base_path, folder_name))
    base_prefix = base_path.rstrip(os.sep) + os.sep
    if target_path != base_path and not target_path.startswith(base_prefix):
        raise HTTPException(status_code=403, detail="Invalid target path")

    if not is_safe_path(target_path):
        raise HTTPException(status_code=403, detail="Access to target path is forbidden")

    if os.path.exists(target_path):
        raise HTTPException(status_code=409, detail="Target folder already exists")

    try:
        result = subprocess.run(
            ["git", "clone", "--", repo_url, target_path],
            cwd=base_path,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="git is not installed on this server")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="git clone timed out")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to execute git clone: {str(e)}")

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "git clone failed").strip()
        raise HTTPException(status_code=400, detail=detail[:1000])

    database.log_audit(
        user["username"],
        "git_clone_repository",
        f"Cloned repository '{repo_url}' into '{target_path}'",
    )

    return {
        "status": "cloned",
        "repo_url": repo_url,
        "path": target_path,
        "folder_name": folder_name,
    }


@router.post("/chmod")
def change_permissions(data: FilePermissionsRequest, user=Depends(require_role("admin"))):
    if not is_safe_path(data.path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(data.path):
        raise HTTPException(status_code=404, detail="Path not found")

    try:
        if not re.match(r"^[0-7]{3}$", data.permissions):
            raise HTTPException(status_code=400, detail="Invalid permissions format (use 3 octal digits)")

        mode = int(data.permissions, 8)
        os.chmod(data.path, mode)

        database.log_audit(user["username"], "change_permissions", f"Changed permissions of {data.path} to {data.permissions}")

        return {"status": "updated", "path": data.path, "permissions": data.permissions}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid permissions format")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to change permissions: {str(e)}")


@router.get("/download")
def download_file(path: str, user=Depends(require_role("operator"))):
    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path) or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found")

    database.log_audit(user["username"], "download_file", f"Downloaded file: {path}")
    return FileResponse(path, filename=os.path.basename(path))


@router.get("/download-folder")
def download_folder(path: str, user=Depends(require_role("operator"))):
    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path) or not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Directory not found")

    folder_name = os.path.basename(path.rstrip(os.sep)) or "folder"
    tmp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp_zip_path = tmp_zip.name
    tmp_zip.close()

    try:
        shutil.make_archive(tmp_zip_path.replace(".zip", ""), "zip", path)
        database.log_audit(user["username"], "download_folder", f"Downloaded folder: {path}")

        def _cleanup():
            try:
                os.unlink(tmp_zip_path)
            except OSError:
                pass

        return FileResponse(
            tmp_zip_path,
            media_type="application/zip",
            filename=f"{folder_name}.zip",
            background=BackgroundTask(_cleanup),
        )
    except Exception as e:
        try:
            os.unlink(tmp_zip_path)
        except OSError:
            pass
        raise HTTPException(status_code=500, detail=f"Failed to create zip: {str(e)}")


@router.post("/upload")
async def upload_file(path: str, file: UploadFile = File(...), user=Depends(require_role("admin"))):
    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path) or not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Target directory not found")

    target_path = os.path.join(path, file.filename)
    if not is_safe_path(target_path):
        raise HTTPException(status_code=403, detail="Access to target path is forbidden")

    try:
        with open(target_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        database.log_audit(user["username"], "upload_file", f"Uploaded file: {target_path}")
        return {"status": "uploaded", "path": target_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload file: {str(e)}")


@router.post("/upload-folder")
async def upload_folder(path: str, files: list[UploadFile] = File(...), paths: list[str] = Form(default=[]), user=Depends(require_role("admin"))):
    if not is_safe_path(path):
        raise HTTPException(status_code=403, detail="Access to this path is forbidden")

    if not os.path.exists(path) or not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Target directory not found")

    relative_paths = [p.strip() for p in paths if p.strip()] if paths else []

    if len(relative_paths) != len(files):
        relative_paths = [f.filename for f in files]

    uploaded = []
    errors = []
    for file_obj, rel_path in zip(files, relative_paths):
        try:
            safe_rel = rel_path.replace("\\", "/")
            while safe_rel.startswith("/"):
                safe_rel = safe_rel[1:]
            if ".." in safe_rel.split("/"):
                errors.append({"file": rel_path, "error": "Path traversal not allowed"})
                continue

            target_path = os.path.join(path, safe_rel)
            if not is_safe_path(target_path):
                errors.append({"file": rel_path, "error": "Access to target path is forbidden"})
                continue

            target_dir = os.path.dirname(target_path)
            os.makedirs(target_dir, exist_ok=True)

            with open(target_path, "wb") as buffer:
                shutil.copyfileobj(file_obj.file, buffer)

            uploaded.append(target_path)
        except Exception as e:
            errors.append({"file": rel_path, "error": str(e)})

    if uploaded:
        database.log_audit(user["username"], "upload_folder", f"Uploaded {len(uploaded)} file(s) to {path}")

    return {"status": "completed", "uploaded": len(uploaded), "errors": len(errors), "files": uploaded, "error_details": errors}
