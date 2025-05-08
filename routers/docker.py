import docker
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.models import User
from app.user_manager import get_current_user_cli

client = docker.from_env()

router = APIRouter()


class RunSpec(BaseModel):
    image: str
    name: str
    mem_limit: str = "512m"
    cpu_quota: int = 50000  # 50% of single CPU


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
