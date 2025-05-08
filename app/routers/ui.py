import docker
import logging
from pathlib import Path
from typing import List

from fastapi import (
    APIRouter, Request,
    Depends, HTTPException,
    status, Form
)
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from app import auth, models
from app.models import User
from app.user_manager import get_current_user

logger = logging.getLogger("ui")
docker_client = docker.from_env()
router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


async def is_user_in_group(user: models.User, group_name: str):
    groups = await user.groups.all()
    return any(group.name == group_name for group in groups)


async def check_access(user: User):
    if not (
            await is_user_in_group(user, "administrators")
            or await is_user_in_group(user, "managers")
    ):
        raise HTTPException(status_code=403, detail="Permission denied")


@router.get("/", response_class=HTMLResponse)
async def containers_ui(request: Request,
                        user: User = Depends(get_current_user)):
    await check_access(user)
    containers = docker_client.containers.list(
        all=True,
        filters={"label": f"owner={user.id}"}
    )
    return templates.TemplateResponse("containers.html", {
        "request": request,
        "containers": containers
    })


@router.get("/run", response_class=HTMLResponse)
async def run_form(request: Request,
                   user: User = Depends(get_current_user)):
    await check_access(user)
    return templates.TemplateResponse("run_container.html", {
        "request": request
    })


@router.post("/run")
async def run_submit(
        request: Request,
        image: str = Form(...),
        name: str = Form(...),
        mem_limit: str = Form("512m"),
        cpu_quota: int = Form(50000),
        volumes: str = Form(""),  # comma-separated
        user: User = Depends(get_current_user),
):
    await check_access(user)

    # Парсим volumes: "host:cont[:mode],..."
    vol_list = [v.strip() for v in volumes.split(",") if v.strip()]
    volumes_map = {}
    for vol in vol_list:
        parts = vol.split(":", 2)
        raw_host, container_path = parts[0], parts[1]
        mode = parts[2] if len(parts) == 3 else "rw"
        host_path = Path(raw_host).expanduser().resolve()
        if not host_path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"Host path '{host_path}' does not exist"
            )
        volumes_map[host_path.as_posix()] = {"bind": container_path, "mode": mode}

    docker_client.containers.run(
        image,
        name=name,
        detach=True,
        mem_limit=mem_limit,
        cpu_quota=cpu_quota,
        labels={"owner": str(user.id)},
        volumes=volumes_map or None
    )
    return RedirectResponse("/ui", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{ctr_id}/start")
async def ui_start(ctr_id: str,
                   user: User = Depends(get_current_user)):
    await check_access(user)
    ctr = docker_client.containers.get(ctr_id)
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(status_code=403)
    ctr.start()
    return RedirectResponse("/ui", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{ctr_id}/stop")
async def ui_stop(ctr_id: str,
                  user: User = Depends(get_current_user)):
    await check_access(user)
    ctr = docker_client.containers.get(ctr_id)
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(status_code=403)
    ctr.stop()
    return RedirectResponse("/ui", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{ctr_id}/remove")
async def ui_remove(ctr_id: str,
                    user: User = Depends(get_current_user)):
    await check_access(user)
    ctr = docker_client.containers.get(ctr_id)
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(status_code=403)
    ctr.remove(force=True)
    return RedirectResponse("/ui", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/images", response_class=HTMLResponse)
async def images_ui(request: Request,
                    user: User = Depends(get_current_user)):
    await check_access(user)
    cntrs = docker_client.containers.list(
        all=True,
        filters={"label": f"owner={user.id}"}
    )
    img_ids = {c.image.id for c in cntrs}
    images = []
    for img_id in img_ids:
        try:
            img = docker_client.images.get(img_id)
            images.append(img)
        except docker.errors.ImageNotFound:
            pass
    return templates.TemplateResponse("images.html", {
        "request": request,
        "images": images
    })


@router.post("/images/{image_id}/remove")
async def ui_remove_image(image_id: str,
                          user: User = Depends(get_current_user)):
    await check_access(user)
    cntrs = docker_client.containers.list(
        all=True,
        filters={"label": f"owner={user.id}", "ancestor": image_id}
    )
    if any(c.status != "exited" for c in cntrs):
        raise HTTPException(
            status_code=400,
            detail="Cannot remove image: running containers exist"
        )
    docker_client.images.remove(image=image_id)
    return RedirectResponse("/ui/images", status_code=status.HTTP_303_SEE_OTHER)
