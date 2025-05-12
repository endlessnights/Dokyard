# app/routers/stacks/.py
import os
import platform
import logging
import re
import secrets
from datetime import datetime

import asyncpg
import docker

from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from fastapi import (
    APIRouter,
    Request,
    Depends,
    HTTPException,
    status,
    Form,
    UploadFile,
    File, Body,
)
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.responses import JSONResponse

from app.models import User, ComposeStack, UserDatabase
from app.user_manager import get_current_user
from app.routers.docker import run_compose as api_run_compose, ComposeSpec

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger("ui")
docker_client = docker.from_env()

SALT_WORDS = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet",
    "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango",
    "uniform", "victor", "whiskey", "xray", "yankee", "zulu", "amber", "boulder", "cobalt", "dune",
    "ember", "flint", "granite", "harbor", "isle", "jade", "keel", "lagoon", "marble", "nebula",
    "onyx", "pearl", "quartz", "ripple", "sapphire", "timber", "umber", "vertex", "willow", "xenon",
    "yellow", "zephyr", "aurora", "banyan", "cascade", "drift", "fjord", "grove", "hollow",
    "oslo", "kyoto", "dublin", "vienna", "madrid", "paris", "berlin", "prague", "rome", "lisbon",
    "athens", "helsinki", "zurich", "warsaw", "riga", "vilnius", "stockholm", "cairo", "jakarta",
    "sydney", "moscow", "baku", "seoul", "delhi", "beijing", "hanoi", "bangkok", "manila", "doha",
    "tbilisi", "amsterdam", "brussels", "sofia", "bucharest", "reykjavik", "nairobi", "capetown",
    "lagos", "kinshasa", "santiago", "quito", "lima", "caracas", "bogota", "montevideo", "osaka",
    "dubai", "riyadh", "kigali", "accra", "almaty", "aktau", "astana", "bishkek", "tashkent",
    "kabul", "isfahan", "tehran", "newyork", "boston", "seattle", "miami", "houston"
]


def get_fernet() -> Fernet:
    key = os.getenv("FERNET_KEY", "FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY not set in env")
    return Fernet(key)


def simplify_docker_error(e: docker.errors.APIError) -> str:
    match = re.search(r'(?<=Error \(")(.*?)(?="\))', str(e))
    return match.group(1) if match else str(e)


async def is_user_in_group(user: User, group_name: str) -> bool:
    groups = await user.groups.all()
    return any(g.name == group_name for g in groups)


async def check_access(user: User):
    if not (
            await is_user_in_group(user, "administrators")
            or await is_user_in_group(user, "users")
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
    error = request.session.pop("error", None)

    containers = docker_client.containers.list(
        all=True, filters={"label": f"owner={user.id}"}
    )
    container_infos = []
    for c in containers:
        started_at = c.attrs["State"].get("StartedAt")
        container_infos.append(
            {
                "object": c,
                "started_at": started_at,
                "running": c.attrs["State"].get("Running", False),
            }
        )
    return templates.TemplateResponse(
        "containers.html",
        {"request": request, "containers": container_infos, "error": error},
    )


@router.get("/run", response_class=HTMLResponse)
async def run_form(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)
    return templates.TemplateResponse(
        "run_container.html",
        {
            "request": request,
            "used_ports": get_used_host_ports(),
            "form_data": {},
            "error": None,
        },
    )


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

        return RedirectResponse("/stacks/", status_code=status.HTTP_303_SEE_OTHER)

    except (ValueError, docker.errors.APIError) as e:
        return templates.TemplateResponse(
            "run_container.html",
            {
                "request": request,
                "used_ports": get_used_host_ports(),
                "error": str(e),
                "form_data": form_data,
            },
        )


@router.get("/compose", response_class=HTMLResponse)
async def compose_form(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)
    return templates.TemplateResponse("compose.html", {"request": request})


@router.post("/compose", response_class=HTMLResponse)
async def compose_submit(
        compose_file: UploadFile = File(None),
        compose_text: str = Form(""),
        stack_id: Optional[str] = Form(None),
        request: Request = None,
        user: User = Depends(get_current_user),
):
    await check_access(user)

    file_content = ""
    if compose_file and compose_file.filename:
        file_content = (await compose_file.read()).decode()

    content = file_content.strip() or compose_text.strip()

    if not content:
        return templates.TemplateResponse(
            "compose.html",
            {
                "request": request,
                "error": "No compose file or text provided.",
                "compose_text": compose_text,
                "stack_id": stack_id,
            },
        )

    # если стек редактируется — удаляем текущие контейнеры
    if stack_id:
        containers = docker_client.containers.list(
            all=True, filters={"label": f"stack_id={stack_id}"}
        )
        for ctr in containers:
            try:
                ctr.stop()
            except:
                pass
            try:
                ctr.remove(force=True)
            except:
                pass

        # перезаписываем YAML
        stack = await ComposeStack.get_or_none(stack_id=stack_id, owner=user)
        if stack:
            stack.compose_yaml = content
            await stack.save()

    # запускаем как новый стек
    try:
        result = await api_run_compose(
            ComposeSpec(compose_yaml=content), user, existing_stack_id=stack_id
        )
    except HTTPException as e:
        return templates.TemplateResponse(
            "compose.html",
            {
                "request": request,
                "error": e.detail,
                "compose_text": content,
            },
        )

    return RedirectResponse("/stacks/", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/stacks/{stack_id}/edit", response_class=HTMLResponse)
async def stack_edit(
        stack_id: str, request: Request, user: User = Depends(get_current_user)
):
    await check_access(user)
    stack = await ComposeStack.get_or_none(stack_id=stack_id, owner=user)
    if not stack:
        raise HTTPException(404, "Stack not found")
    return templates.TemplateResponse(
        "compose.html",
        {
            "request": request,
            "compose_text": stack.compose_yaml,
            "stack_id": stack.stack_id,
        },
    )


@router.post("/stacks/{stack_id}/start")
async def ui_stack_start(stack_id: str, user: User = Depends(get_current_user)):
    await check_access(user)
    containers = docker_client.containers.list(
        all=True, filters={"label": f"owner={user.id}", "label": f"stack_id={stack_id}"}
    )
    for c in containers:
        try:
            c.start()
        except:
            continue
    return RedirectResponse("/stacks/", status_code=303)


@router.post("/stacks/{stack_id}/stop")
async def ui_stack_stop(stack_id: str, user: User = Depends(get_current_user)):
    await check_access(user)
    containers = docker_client.containers.list(
        all=True, filters={"label": f"owner={user.id}", "label": f"stack_id={stack_id}"}
    )
    for c in containers:
        try:
            c.stop()
        except:
            continue
    return RedirectResponse("/stacks/", status_code=303)


@router.get("/logs/{ctr_id}", response_class=HTMLResponse)
async def ui_container_logs(
        ctr_id: str, request: Request, user: User = Depends(get_current_user)
):
    await check_access(user)
    try:
        ctr = docker_client.containers.get(ctr_id)
    except docker.errors.NotFound:
        raise HTTPException(404, "Container not found")
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, "Not your container")
    try:
        logs = ctr.logs(tail=1000).decode()
    except Exception as e:
        logs = f"Error reading logs: {e}"
    return templates.TemplateResponse(
        "logs.html", {"request": request, "container": ctr, "logs": logs}
    )


@router.post("/{ctr_id}/start")
async def ui_start(
        ctr_id: str, request: Request, user: User = Depends(get_current_user)
):
    await check_access(user)
    try:
        ctr = docker_client.containers.get(ctr_id)
        if ctr.labels.get("owner") != str(user.id):
            raise HTTPException(403, detail="Not your container")
        ctr.start()
    except Exception as e:
        request.session["error"] = str(e)
    return RedirectResponse("/stacks/", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{ctr_id}/stop")
@router.post("/{ctr_id}/stop")
async def ui_stop(ctr_id: str, user: User = Depends(get_current_user)):
    await check_access(user)
    ctr = docker_client.containers.get(ctr_id)
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, detail="Not your container")
    ctr.stop()
    return RedirectResponse("/stacks/", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{ctr_id}/remove")
@router.post("/{ctr_id}/remove")
async def ui_remove(ctr_id: str, user: User = Depends(get_current_user)):
    await check_access(user)
    ctr = docker_client.containers.get(ctr_id)
    if ctr.labels.get("owner") != str(user.id):
        raise HTTPException(403, detail="Not your container")
    ctr.remove(force=True)
    return RedirectResponse("/stacks/", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/images", response_class=HTMLResponse)
async def images_ui(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)

    # Все контейнеры пользователя
    user_cntrs = docker_client.containers.list(
        all=True, filters={"label": f"owner={user.id}"}
    )
    image_ids = {c.image.id for c in user_cntrs}
    containers_by_image = {}
    for c in user_cntrs:
        containers_by_image.setdefault(c.image.id, []).append(c)

    images = []
    for image_id in image_ids:
        try:
            img = docker_client.images.get(image_id)
        except docker.errors.ImageNotFound:
            continue

        # Получаем данные
        short_id = image_id.split(":")[1]
        created_raw = img.attrs["Created"]
        created_iso = created_raw.replace("Z", "+00:00")
        created = datetime.fromisoformat(created_iso).strftime("%Y-%m-%d %H:%M:%S UTC")
        size_mb = round(img.attrs["Size"] / 1024 / 1024, 2)
        tags = img.tags or ["<none>:<none>"]

        statuses = [c.status for c in containers_by_image[image_id]]
        status = (
            "In use (running)"
            if any(s == "running" for s in statuses)
            else "In use (stopped)"
        )

        images.append(
            {
                "id": short_id,
                "tags": tags,
                "size_mb": size_mb,
                "created_iso": created_iso,
                "status": status,
            }
        )

    return templates.TemplateResponse(
        "images.html", {"request": request, "images": images}
    )


@router.post("/images/{image_id}/remove")
async def ui_remove_image(
        image_id: str,
        request: Request,
        user: User = Depends(get_current_user),
):
    await check_access(user)

    # Собираем контейнеры пользователя
    user_cntrs = docker_client.containers.list(
        all=True, filters={"label": f"owner={user.id}"}
    )
    image_ids = {c.image.id for c in user_cntrs}
    containers_by_image = {}
    for c in user_cntrs:
        containers_by_image.setdefault(c.image.id, []).append(c)

    try:
        full_image_id = None
        # находим полное id
        for img in docker_client.images.list():
            if image_id in img.id:
                full_image_id = img.id
                break

        if not full_image_id:
            raise ValueError("Image not found")

        # Проверяем, используется ли образ
        if full_image_id in containers_by_image:
            statuses = [c.status for c in containers_by_image[full_image_id]]
            if any(s != "exited" for s in statuses):
                raise ValueError("Image is used by running containers")

        # Удаляем
        docker_client.images.remove(image=full_image_id)

        return RedirectResponse("/stacks//images", status_code=303)

    except Exception as e:
        # Возвращаем шаблон с ошибкой и текущим списком образов
        images = []
        for image_id in image_ids:
            try:
                img = docker_client.images.get(image_id)
                short_id = img.id.split(":")[1]
                created_iso = img.attrs["Created"].replace("Z", "+00:00")
                created = datetime.fromisoformat(created_iso).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                size_mb = round(img.attrs["Size"] / 1024 / 1024, 2)
                tags = img.tags or ["<none>:<none>"]
                statuses = [c.status for c in containers_by_image[image_id]]
                status = (
                    "In use (running)"
                    if any(s == "running" for s in statuses)
                    else "In use (stopped)"
                )

                images.append(
                    {
                        "id": short_id,
                        "tags": tags,
                        "size_mb": size_mb,
                        "created": created,
                        "status": status,
                    }
                )
            except docker.errors.ImageNotFound:
                continue

        return templates.TemplateResponse(
            "images.html", {"request": request, "images": images, "error": str(e)}
        )


@router.get("/databases", response_class=HTMLResponse)
async def databases_ui(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)
    dbs = await UserDatabase.filter(owner=user).order_by("-created_at")
    # вытащим единоразочные данные из сессии, если они есть
    new_db = request.session.pop("new_db", None)
    revealed = request.session.pop("revealed", {})
    salt_error = request.session.pop("salt_error", None)

    return templates.TemplateResponse("databases.html", {
        "request": request,
        "databases": dbs,
        "new_db": new_db,
        "revealed": revealed,
        "salt_error": salt_error
    })


@router.post("/databases/create", response_class=HTMLResponse)
async def create_database(
        request: Request,
        name: str = Form(...),
        user: User = Depends(get_current_user)
):
    await check_access(user)
    if await UserDatabase.filter(owner=user).count() >= 3:
        request.session["salt_error"] = "You have reached the limit of 3 databases"
        return RedirectResponse("/stacks/databases", 303)

    # генерим креды
    db_user = f"{user.username}_{secrets.token_hex(3)}"
    raw_password = secrets.token_urlsafe(12)
    salt = "-".join(secrets.choice(SALT_WORDS) for _ in range(3))
    f = get_fernet()
    encrypted = f.encrypt(raw_password.encode()).decode()

    # создаём реальную БД
    try:
        conn = await asyncpg.connect(
            user=os.getenv("POSTGRES_USER_USER"),
            password=os.getenv("POSTGRES_USER_PASSWORD"),
            database=os.getenv("POSTGRES_USER_DB"),
            host=os.getenv("PGDB_USER_HOST", "pgdb_user"),
            port=int(os.getenv("PGDB_USER_PORT", 5432)),
        )
        await conn.execute(f'CREATE USER "{db_user}" WITH PASSWORD \'{raw_password}\';')
        await conn.execute(f'CREATE DATABASE "{name}" OWNER "{db_user}";')
        await conn.close()
    except Exception as e:
        request.session["salt_error"] = f"Postgres error: {e}"
        return RedirectResponse("/stacks/databases", 303)

    # сохраняем мета
    db = await UserDatabase.create(
        name=name,
        owner=user,
        db_user=db_user,
        db_password_encrypted=encrypted,
        salt_phrase=salt
    )

    # передадим единоразочно в UI
    request.session["new_db"] = {
        "id": db.id, "name": name,
        "db_user": db_user,
        "password": raw_password,
        "salt": salt
    }
    return RedirectResponse("/stacks/databases", 303)


class RevealRequest(BaseModel):
    salt: str


@router.post("/databases/{db_id}/reveal")
async def reveal_database(
        db_id: int,
        payload: RevealRequest = Body(...),
        user: User = Depends(get_current_user)
):
    await check_access(user)
    # находим запись
    db = await UserDatabase.get_or_none(id=db_id, owner=user)
    if not db:
        return JSONResponse({"success": False, "error": "Database not found"})
    # проверяем salt
    if payload.salt != db.salt_phrase:
        return JSONResponse({"success": False, "error": "Invalid salt"})
    # расшифровываем пароль
    f = get_fernet()
    raw = f.decrypt(db.db_password_encrypted.encode()).decode()
    return JSONResponse({"success": True, "password": raw})


@router.get("/fs", response_class=HTMLResponse)
async def fs_browser(
        request: Request, path: str = "", user: User = Depends(get_current_user)
):
    await check_access(user)
    base = get_home_base(user)
    target = (base / path).resolve()
    if not str(target).startswith(str(base)):
        raise HTTPException(400, detail="Invalid path")
    if not target.exists():
        raise HTTPException(404, detail="Not found")

    entries = []
    for p in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        entries.append(
            {
                "name": p.name,
                "is_dir": p.is_dir(),
                "rel": p.relative_to(base).as_posix(),
            }
        )

    current = Path(path).as_posix().rstrip("/")
    return templates.TemplateResponse(
        "fs_browser.html", {"request": request, "entries": entries, "current": current}
    )


@router.post("/fs/upload")
async def fs_upload(
        path: str = Form(""),
        file: UploadFile = File(...),
        user: User = Depends(get_current_user),
):
    await check_access(user)
    base = get_home_base(user)
    dest_dir = (base / path).resolve()
    if not dest_dir.is_dir() or not str(dest_dir).startswith(str(base)):
        raise HTTPException(400, detail="Invalid upload directory")
    dest = dest_dir / file.filename
    with open(dest, "wb") as f:
        f.write(await file.read())
    return RedirectResponse(
        f"/stacks//fs?path={path}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/fs/download")
async def fs_download(path: str, user: User = Depends(get_current_user)):
    await check_access(user)
    base = get_home_base(user)
    target = (base / path).resolve()
    if not str(target).startswith(str(base)) or not target.is_file():
        raise HTTPException(400, detail="Invalid file")
    return FileResponse(str(target), filename=target.name)


@router.get("/dockerhub", response_class=HTMLResponse)
async def dockerhub_auth_form(request: Request, user: User = Depends(get_current_user)):
    await check_access(user)
    return templates.TemplateResponse(
        "dockerhub_login.html",
        {"request": request, "dockerhub_user": request.session.get("dockerhub_user")},
    )


@router.post("/dockerhub")
async def dockerhub_auth_submit(
        request: Request,
        username: str = Form(...),
        token: str = Form(...),
        user: User = Depends(get_current_user),
):
    await check_access(user)
    docker_client = docker.from_env()
    try:
        docker_client.login(
            username=username, password=token, registry="https://index.docker.io/v1/"
        )
    except docker.errors.APIError as e:
        return templates.TemplateResponse(
            "dockerhub_login.html",
            {
                "request": request,
                "error": f"Failed to authenticate: {e.explanation}",
                "dockerhub_user": None,
            },
        )

    request.session["dockerhub_user"] = username
    return RedirectResponse("/stacks//dockerhub", status_code=303)
