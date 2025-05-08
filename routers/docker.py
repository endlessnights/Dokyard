import docker
import yaml
import logging

from pathlib import Path
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.models import User
from app.user_manager import get_current_user_cli

logger = logging.getLogger("docker-compose")
client = docker.from_env()
router = APIRouter()


class RunSpec(BaseModel):
    image: str
    name: str
    mem_limit: str = "512m"
    cpu_quota: int = 50000  # 50% of single CPU
    volumes: List[str] = Field(
        default_factory=list,
        description="Тома в формате host_path:container_path[:mode], можно несколько"
    )


@router.post("/run")
async def run_container(
    spec: RunSpec,
    user: User = Depends(get_current_user_cli)
):
    labels = {"owner": str(user.id)}

    # Преобразуем список volumes в формат docker-py, проверяем пути
    volumes_map = {}
    for vol in spec.volumes:
        parts = vol.split(":", 2)
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail=f"Invalid volume spec: {vol}")
        raw_host, container_path = parts[0], parts[1]
        mode = parts[2] if len(parts) == 3 else "rw"

        host_path = Path(raw_host).expanduser().resolve()
        if not host_path.exists():
            raise HTTPException(status_code=400, detail=f"Host path '{host_path}' does not exist")
        volumes_map[host_path.as_posix()] = {"bind": container_path, "mode": mode}

    try:
        ctr = client.containers.run(
            spec.image,
            name=spec.name,
            detach=True,
            mem_limit=spec.mem_limit,
            cpu_quota=spec.cpu_quota,
            labels=labels,
            volumes=volumes_map or None
        )
    except docker.errors.APIError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"id": ctr.id, "status": ctr.status}


class ComposeSpec(BaseModel):
    compose_yaml: str


@router.post("/compose")
async def run_compose(
    spec: ComposeSpec,
    user: User = Depends(get_current_user_cli)
):
    try:
        doc = yaml.safe_load(spec.compose_yaml)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")

    services = doc.get("services")
    if not isinstance(services, dict):
        raise HTTPException(status_code=400, detail="`services` must be a mapping")

    created = []
    for svc_name, svc_cfg in services.items():
        image = svc_cfg.get("image")
        if not image:
            continue

        labels = {"owner": str(user.id)}
        run_kwargs = {"detach": True, "labels": labels}

        # Порты
        if "ports" in svc_cfg:
            ports_map = {}
            for mapping in svc_cfg["ports"]:
                host_port, container_port = mapping.split(":", 1)
                ports_map[int(container_port)] = int(host_port)
            run_kwargs["ports"] = ports_map

        # Окружение
        if "environment" in svc_cfg:
            run_kwargs["environment"] = svc_cfg["environment"]

        # Тома
        if "volumes" in svc_cfg:
            volumes_map = {}
            for vol in svc_cfg["volumes"]:
                parts = vol.split(":", 2)
                if len(parts) < 2:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid volume spec for service {svc_name}: '{vol}'"
                    )
                raw_host, container_path = parts[0], parts[1]
                mode = parts[2] if len(parts) == 3 else "rw"

                host_path = Path(raw_host).expanduser().resolve()
                if not host_path.exists():
                    raise HTTPException(
                        status_code=400,
                        detail=f"Host path '{host_path}' does not exist for service {svc_name}"
                    )
                volumes_map[host_path.as_posix()] = {"bind": container_path, "mode": mode}

            run_kwargs["volumes"] = volumes_map

        try:
            ctr = client.containers.run(
                image,
                name=f"{user.id}_{svc_name}",
                **run_kwargs
            )
            created.append({"service": svc_name, "id": ctr.id})
        except docker.errors.APIError as e:
            logger.exception(f"Failed to start service {svc_name}")
            raise HTTPException(status_code=400, detail=f"{svc_name}: {e}")

    return {"containers": created}


@router.get("/")
async def list_containers(user: User = Depends(get_current_user_cli)):
    all_ctr = client.containers.list(all=True, filters={"label": f"owner={user.id}"})
    return [{"id": ctr.id, "name": ctr.name, "status": ctr.status} for ctr in all_ctr]


@router.delete("/{ctr_id}")
async def remove_container(
    ctr_id: str,
    user: User = Depends(get_current_user_cli)
):
    try:
        ctr = client.containers.get(ctr_id)
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Container not found")
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(status_code=403, detail="Not your container")
    ctr.remove(force=True)
    return {"removed": ctr_id}
