# app/routers/ui.py
import os
import platform
import logging
import re

import yaml
import docker

from pathlib import Path
from typing import List

from fastapi import (
    APIRouter, Request,
    Depends, HTTPException,
    status, Form, UploadFile, File
)
from fastapi.responses import (
    HTMLResponse, RedirectResponse, FileResponse
)
from fastapi.templating import Jinja2Templates

from app.models import User
from app.user_manager import get_current_user
from routers.docker import run_compose as api_run_compose, ComposeSpec

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger("ui")
docker_client = docker.from_env()


def simplify_docker_error(e: docker.errors.APIError) -> str:
    match = re.search(r'(?<=Error \(")(.*?)(?="\))', str(e))
    return match.group(1) if match else str(e)


async def is_user_in_group(user: User, group_name: str) -> bool:
    groups = await user.groups.all()
    return any(g.name == group_name for g in groups)


async def check_access(user: User):
    if not (
        await is_user_in_group(user, "administrators")
        or await is_user_in_group(user, "managers")
    ):
        raise HTTPException(status_code=403, detail="Permission denied")


def get_home_base(user: User) -> Path:
    if platform.system() == "Windows":
        return Path(r"C:\Users\baymu\PycharmProjects\clubdocker\cli\tmp").resolve()
    else:
        return (Path("/home/clubdocker") / user.username).resolve()


def get_used_host_ports() -> set:
    used = set()
    for c in docker_client.containers.list(all=True):
        ports = c.attrs.get("NetworkSettings", {}).get("Ports") or {}
        for mappings in ports.values():
            if mappings:
                for m in mappings:
                    try:
                        used.add(int(m["HostPort"]))
                    except:
                        pass
    return used


@router.get("/", response_class=HTMLResponse)
async def containers_ui(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)
    containers = docker_client.containers.list(
        all=True, filters={"label": f"owner={user.id}"}
    )
    return templates.TemplateResponse("containers.html", {
        "request": request,
        "containers": containers
    })


@router.get("/run", response_class=HTMLResponse)
async def run_form(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)
    return templates.TemplateResponse("run_container.html", {
        "request": request,
        "used_ports": get_used_host_ports(),
        "form_data": {},
        "error": None,
    })


@router.post("/run", response_class=HTMLResponse)
async def run_submit(
    request: Request,
    image: str = Form(...),
    name: str = Form(...),
    mem_limit: str = Form("512m"),
    cpu_quota: int = Form(50000),
    ports: str = Form(""),
    envs: str = Form(""),
    volumes: str = Form(""),
    user: User = Depends(get_current_user),
):
    await check_access(user)

    form_data = {
        "image": image,
        "name": name,
        "mem_limit": mem_limit,
        "cpu_quota": str(cpu_quota),
        "ports": ports,
        "envs": envs,
        "volumes": volumes,
    }

    try:
        ports_map = {}
        for p in ports.split(","):
            p = p.strip()
            if not p:
                continue
            host, cont = map(int, p.split(":"))
            if host in get_used_host_ports():
                raise ValueError(f"Port {host} already in use")
            ports_map[cont] = host

        env_map = {}
        for e in envs.split(","):
            e = e.strip()
            if not e:
                continue
            if "=" not in e:
                raise ValueError(f"Invalid env var: {e}")
            k, v = e.split("=", 1)
            env_map[k] = v

        volumes_map = {}
        for v in volumes.split(","):
            v = v.strip()
            if not v:
                continue
            parts = v.split(":", 2)
            if len(parts) < 2:
                raise ValueError(f"Invalid volume: {v}")
            raw_host, cont_path = parts[0], parts[1]
            mode = parts[2] if len(parts) == 3 else "rw"
            host_path = Path(raw_host).expanduser().resolve()
            if not host_path.exists():
                raise ValueError(f"Path not found: {host_path}")
            volumes_map[host_path.as_posix()] = {"bind": cont_path, "mode": mode}

        docker_client.containers.run(
            image,
            name=name,
            detach=True,
            mem_limit=mem_limit,
            cpu_quota=cpu_quota,
            labels={"owner": str(user.id)},
            ports=ports_map or None,
            environment=env_map or None,
            volumes=volumes_map or None,
        )

        return RedirectResponse("/ui", status_code=status.HTTP_303_SEE_OTHER)

    except (ValueError, docker.errors.APIError) as e:
        return templates.TemplateResponse("run_container.html", {
            "request": request,
            "used_ports": get_used_host_ports(),
            "error": str(e),
            "form_data": form_data
        })


@router.get("/compose", response_class=HTMLResponse)
async def compose_form(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)
    return templates.TemplateResponse("compose.html", {"request": request})


@router.post("/compose", response_class=HTMLResponse)
async def compose_submit(
    compose_file: UploadFile = File(None),
    compose_text: str = Form(""),
    request: Request = None,
    user: User = Depends(get_current_user),
):
    await check_access(user)

    # Получение содержимого
    content = ""
    if compose_file:
        try:
            content = (await compose_file.read()).decode()
        except Exception:
            return templates.TemplateResponse("compose.html", {
                "request": request,
                "error": "Failed to read uploaded file.",
                "compose_text": ""
            })
    else:
        content = compose_text.strip()

    # Если ничего не передано
    if not content:
        return templates.TemplateResponse("compose.html", {
            "request": request,
            "error": "No compose file or text provided.",
            "compose_text": ""
        })

    # Проверка YAML перед выполнением
    try:
        doc = yaml.safe_load(content)
        if not isinstance(doc, dict) or "services" not in doc:
            raise ValueError("Invalid or empty compose YAML: no 'services' section found")
    except Exception as e:
        return templates.TemplateResponse("compose.html", {
            "request": request,
            "error": f"YAML error: {e}",
            "compose_text": content
        })

    # Запуск
    try:
        result = await api_run_compose(ComposeSpec(compose_yaml=content), user)
    except HTTPException as e:
        return templates.TemplateResponse("compose.html", {
            "request": request,
            "error": e.detail,
            "compose_text": content
        })

    return templates.TemplateResponse("compose_result.html", {
        "request": request,
        "containers": result["containers"]
    })


@router.get("/{ctr_id}/start")
@router.post("/{ctr_id}/start")
async def ui_start(ctr_id: str, user: User = Depends(get_current_user)):
    await check_access(user)
    ctr = docker_client.containers.get(ctr_id)
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, detail="Not your container")
    ctr.start()
    return RedirectResponse("/ui", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{ctr_id}/stop")
@router.post("/{ctr_id}/stop")
async def ui_stop(ctr_id: str, user: User = Depends(get_current_user)):
    await check_access(user)
    ctr = docker_client.containers.get(ctr_id)
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, detail="Not your container")
    ctr.stop()
    return RedirectResponse("/ui", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{ctr_id}/remove")
@router.post("/{ctr_id}/remove")
async def ui_remove(ctr_id: str, user: User = Depends(get_current_user)):
    await check_access(user)
    ctr = docker_client.containers.get(ctr_id)
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, detail="Not your container")
    ctr.remove(force=True)
    return RedirectResponse("/ui", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/images", response_class=HTMLResponse)
async def images_ui(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)
    cntrs = docker_client.containers.list(all=True, filters={"label": f"owner={user.id}"})
    img_ids = {c.image.id for c in cntrs}
    images = [docker_client.images.get(iid) for iid in img_ids if docker_client.images.get(iid)]
    return templates.TemplateResponse("images.html", {
        "request": request,
        "images": images
    })


@router.get("/images/{image_id}/remove")
@router.post("/images/{image_id}/remove")
async def ui_remove_image(image_id: str, user: User = Depends(get_current_user)):
    await check_access(user)
    cntrs = docker_client.containers.list(
        all=True,
        filters={"label": f"owner={user.id}", "ancestor": image_id}
    )
    if any(c.status != "exited" for c in cntrs):
        raise HTTPException(400, detail="Containers still running")
    docker_client.images.remove(image=image_id)
    return RedirectResponse("/ui/images", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/fs", response_class=HTMLResponse)
async def fs_browser(request: Request, path: str = "", user: User = Depends(get_current_user)):
    await check_access(user)
    base = get_home_base(user)
    target = (base / path).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(400, detail="Invalid path")
    if not target.exists():
        raise HTTPException(404, detail="Not found")

    entries = []
    for p in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        entries.append({
            "name": p.name,
            "is_dir": p.is_dir(),
            "rel": p.relative_to(base).as_posix()
        })

    current = Path(path).as_posix().rstrip("/")
    return templates.TemplateResponse("fs_browser.html", {
        "request": request,
        "entries": entries,
        "current": current
    })


@router.post("/fs/upload")
async def fs_upload(path: str = Form(""), file: UploadFile = File(...), user: User = Depends(get_current_user)):
    await check_access(user)
    base = get_home_base(user)
    dest_dir = (base / path).resolve()
    if not dest_dir.is_dir() or not str(dest_dir).startswith(str(base)):
        raise HTTPException(400, detail="Invalid upload directory")
    dest = dest_dir / file.filename
    with open(dest, "wb") as f:
        f.write(await file.read())
    return RedirectResponse(f"/ui/fs?path={path}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/fs/download")
async def fs_download(path: str, user: User = Depends(get_current_user)):
    await check_access(user)
    base = get_home_base(user)
    target = (base / path).resolve()
    if not str(target).startswith(str(base)) or not target.is_file():
        raise HTTPException(400, detail="Invalid file")
    return FileResponse(str(target), filename=target.name)
