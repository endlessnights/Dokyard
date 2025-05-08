import docker
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import yaml
import logging
logger = logging.getLogger("docker-compose")

from app.models import User
from app.user_manager import get_current_user_cli

client = docker.from_env()

router = APIRouter()


class RunSpec(BaseModel):
    image: str
    name: str
    mem_limit: str = "512m"
    cpu_quota: int = 50000  # 50% of single CPU


class ComposeSpec(BaseModel):
    """
    Просто обёртка для вашего docker-compose YAML в виде текста.
    """
    compose_yaml: str


@router.post("/run")
async def run_container(spec: RunSpec, user: User = Depends(get_current_user_cli)):
    # 1) проверить квоту: сумма mem_limit юзера + новый > user.quota.mem_total
    # 2) создать контейнер с меткой owner
    labels = {"owner": str(user.id)}
    try:
        ctr = client.containers.run(
            spec.image,
            name=spec.name,
            detach=True,
            mem_limit=spec.mem_limit,
            cpu_quota=spec.cpu_quota,
            labels=labels,
        )
    except docker.errors.APIError as e:
        raise HTTPException(400, str(e))
    return {"id": ctr.id, "status": ctr.status}


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
        raise HTTPException(
            status_code=400,
            detail="`services` must be a mapping of service names to configs"
        )

    created = []
    for svc_name, svc_cfg in services.items():
        image = svc_cfg.get("image")
        if not image:
            continue

        labels = {"owner": str(user.id)}
        run_kwargs: dict = {"detach": True, "labels": labels}

        # --- Вот здесь конвертируем порты из списка в dict ---
        if "ports" in svc_cfg:
            ports_list = svc_cfg["ports"]
            ports_map: dict = {}
            for mapping in ports_list:
                # "HOST:CONTAINER"
                host_port, container_port = mapping.split(":", 1)
                # приводим к int (необязательно, docker-py примет и строки)
                ports_map[int(container_port)] = int(host_port)
            run_kwargs["ports"] = ports_map

        if "environment" in svc_cfg:
            run_kwargs["environment"] = svc_cfg["environment"]

        if "volumes" in svc_cfg:
            run_kwargs["volumes"] = svc_cfg["volumes"]

        try:
            ctr = client.containers.run(
                image,
                name=f"{user.id}_{svc_name}",
                **run_kwargs
            )
            created.append({"service": svc_name, "id": ctr.id})
        except Exception as e:
            logger.exception(f"Failed to start service {svc_name}")
            raise HTTPException(status_code=400, detail=f"{svc_name}: {e}")

    return {"containers": created}


@router.get("/")
async def list_containers(user: User = Depends(get_current_user_cli)):
    # отфильтровать по метке owner
    all_ctr = client.containers.list(all=True, filters={"label": f"owner={user.id}"})
    return [{"id": ctr.id, "name": ctr.name, "status": ctr.status} for ctr in all_ctr]


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
