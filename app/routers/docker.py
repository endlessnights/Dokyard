from uuid import uuid4

import docker
import yaml
import logging

from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from tortoise.transactions import in_transaction

from app.models import User, ComposeStack
from app.user_manager import get_current_user_cli

logger = logging.getLogger("docker-compose")
client = docker.from_env()
router = APIRouter()


class RunSpec(BaseModel):
    image: str
    name: str
    mem_limit: str = "512m"
    cpu_quota: int = 50000
    volumes: List[str] = Field(
        default_factory=list,
        description="host_path:container_path[:mode], можно несколько",
    )


def parse_duration(value: str) -> int:
    if value.endswith("s"):
        return int(value[:-1]) * 1_000_000_000  # seconds to nanoseconds
    if value.endswith("ms"):
        return int(value[:-2]) * 1_000_000
    if value.endswith("m"):
        return int(value[:-1]) * 60 * 1_000_000_000
    raise ValueError(f"Unsupported duration format: {value}")


@router.post("/run")
async def run_container(spec: RunSpec, user: User = Depends(get_current_user_cli)):
    labels = {"owner": str(user.id)}
    volumes_map = {}
    for vol in spec.volumes:
        parts = vol.split(":", 2)
        if len(parts) < 2:
            raise HTTPException(400, f"Invalid volume spec: {vol}")
        raw_host, container_path = parts[0], parts[1]
        mode = parts[2] if len(parts) == 3 else "rw"
        host_path = Path(raw_host).expanduser().resolve()
        if not host_path.exists():
            raise HTTPException(400, f"Host path '{host_path}' does not exist")
        volumes_map[host_path.as_posix()] = {"bind": container_path, "mode": mode}

    try:
        ctr = client.containers.run(
            spec.image,
            name=spec.name,
            detach=True,
            mem_limit=spec.mem_limit,
            cpu_quota=spec.cpu_quota,
            labels=labels,
            volumes=volumes_map or None,
        )
    except docker.errors.APIError as e:
        raise HTTPException(400, str(e))

    return {"id": ctr.id, "status": ctr.status}


class ComposeSpec(BaseModel):
    compose_yaml: str


@router.post("/compose")
async def run_compose(
    spec: ComposeSpec,
    user: User = Depends(get_current_user_cli),
    existing_stack_id: Optional[str] = None,
    mode: str = "strict",  # "strict" or "relaxed"
):
    try:
        doc = yaml.safe_load(spec.compose_yaml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    services = doc.get("services")
    if not isinstance(services, dict):
        raise HTTPException(status_code=400, detail="`services` must be a mapping")

    stack_id = existing_stack_id or str(uuid4())
    created_containers = []
    errors = {}

    for svc_name, svc_cfg in services.items():
        image = svc_cfg.get("image")
        if not image:
            continue

        labels = {
            "owner": str(user.id),
            "stack_id": stack_id,
        }

        run_kwargs = {"detach": True, "labels": labels}

        # Ports
        if "ports" in svc_cfg:
            ports_map = {}
            for mapping in svc_cfg["ports"]:
                try:
                    host_port, container_port = mapping.split(":", 1)
                    ports_map[int(container_port)] = int(host_port)
                except Exception:
                    errors[svc_name] = f"Invalid port mapping: {mapping}"
                    if mode == "strict":
                        break
                    continue
            run_kwargs["ports"] = ports_map

        # Environment
        if "environment" in svc_cfg:
            run_kwargs["environment"] = svc_cfg["environment"]

        # Volumes
        if "volumes" in svc_cfg:
            volumes_map = {}
            for vol in svc_cfg["volumes"]:
                parts = vol.split(":", 2)
                if len(parts) < 2:
                    errors[svc_name] = f"Invalid volume: {vol}"
                    if mode == "strict":
                        break
                    continue
                raw_host, container_path = parts[0], parts[1]
                mode_flag = parts[2] if len(parts) == 3 else "rw"
                host_path = Path(raw_host).expanduser().resolve()
                if not host_path.exists():
                    errors[svc_name] = f"Host path not found: {host_path}"
                    if mode == "strict":
                        break
                    continue
                volumes_map[host_path.as_posix()] = {
                    "bind": container_path,
                    "mode": mode_flag,
                }
            run_kwargs["volumes"] = volumes_map

        # Extra options
        if "hostname" in svc_cfg:
            run_kwargs["hostname"] = svc_cfg["hostname"]
        if "restart" in svc_cfg:
            run_kwargs["restart_policy"] = {"Name": svc_cfg["restart"]}
        if "healthcheck" in svc_cfg:
            raw = svc_cfg["healthcheck"]
            hc = {"test": raw["test"]}

            if "interval" in raw:
                try:
                    hc["interval"] = parse_duration(raw["interval"])
                except ValueError as ve:
                    errors[svc_name] = str(ve)
                    if mode == "strict":
                        break

            if "timeout" in raw:
                try:
                    hc["timeout"] = parse_duration(raw["timeout"])
                except ValueError as ve:
                    errors[svc_name] = str(ve)
                    if mode == "strict":
                        break

            if "retries" in raw:
                hc["retries"] = int(raw["retries"])

            run_kwargs["healthcheck"] = hc

        try:
            ctr = client.containers.run(
                image, name=f"{user.id}_{stack_id[:8]}_{svc_name}", **run_kwargs
            )
            created_containers.append(ctr)
        except docker.errors.APIError as e:
            if mode == "strict":
                for prev_ctr in created_containers:
                    try:
                        prev_ctr.stop()
                    except Exception:
                        pass
                    try:
                        prev_ctr.remove(force=True)
                    except Exception:
                        pass
                raise HTTPException(status_code=400, detail=f"{svc_name}: {str(e)}")
            else:
                errors[svc_name] = str(e)

    if not existing_stack_id:
        await ComposeStack.create(
            stack_id=stack_id, owner=user, compose_yaml=spec.compose_yaml
        )

    if mode == "relaxed" and errors:
        raise HTTPException(status_code=400, detail={"errors": errors})

    return {"containers": [{"id": c.id, "service": c.name} for c in created_containers]}


@router.get("/")
async def list_containers(user: User = Depends(get_current_user_cli)):
    all_ctr = client.containers.list(all=True, filters={"label": f"owner={user.id}"})
    return [{"id": c.id, "name": c.name, "status": c.status} for c in all_ctr]


@router.post("/{ctr_id}/start")
async def start_container(ctr_id: str, user: User = Depends(get_current_user_cli)):
    try:
        ctr = client.containers.get(ctr_id)
    except docker.errors.NotFound:
        raise HTTPException(404, "Container not found")
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, "Not your container")
    try:
        ctr.start()
    except docker.errors.APIError as e:
        raise HTTPException(400, str(e))
    return {"started": ctr_id}


@router.post("/{ctr_id}/stop")
async def stop_container(ctr_id: str, user: User = Depends(get_current_user_cli)):
    try:
        ctr = client.containers.get(ctr_id)
    except docker.errors.NotFound:
        raise HTTPException(404, "Container not found")
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, "Not your container")
    try:
        ctr.stop()
    except docker.errors.APIError as e:
        raise HTTPException(400, str(e))
    return {"stopped": ctr_id}


@router.delete("/{ctr_id}")
async def remove_container(ctr_id: str, user: User = Depends(get_current_user_cli)):
    try:
        ctr = client.containers.get(ctr_id)
    except docker.errors.NotFound:
        raise HTTPException(404, "Container not found")
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, "Not your container")
    ctr.remove(force=True)
    return {"removed": ctr_id}


@router.get("/images")
async def list_images(user: User = Depends(get_current_user_cli)):
    # собираем все контейнеры пользователя
    cntrs = client.containers.list(all=True, filters={"label": f"owner={user.id}"})
    img_ids = {c.image.id for c in cntrs}
    images = []
    for img_id in img_ids:
        try:
            img = client.images.get(img_id)
            images.append({"id": img.id, "tags": img.tags})
        except docker.errors.ImageNotFound:
            continue
    return images


@router.delete("/images/{image_id}")
async def remove_image(image_id: str, user: User = Depends(get_current_user_cli)):
    cntrs = client.containers.list(
        all=True, filters={"label": f"owner={user.id}", "ancestor": image_id}
    )
    running = [c.id for c in cntrs if c.status != "exited"]
    if running:
        raise HTTPException(400, f"Containers still running: {running}")
    try:
        client.images.remove(image=image_id)
    except docker.errors.ImageNotFound:
        raise HTTPException(404, "Image not found")
    except docker.errors.APIError as e:
        raise HTTPException(400, str(e))
    return {"removed_image": image_id}
