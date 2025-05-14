# app/routers/stacks/.py
import base64
import io
import json
import logging
import os
import platform
import re
import secrets
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

import asyncpg
import docker
import httpx
import yaml
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import (APIRouter, Body, Depends, File, Form, HTTPException,
                     Request, UploadFile, status)
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.responses import JSONResponse, StreamingResponse

from app.models import ComposeStack, DockerHubCredential, User, UserDatabase
from app.routers.docker import ComposeSpec
from app.routers.docker import run_compose as api_run_compose
from app.user_manager import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger("ui")
docker_client = docker.from_env()

SALT_WORDS = [
    "alpha",
    "bravo",
    "charlie",
    "delta",
    "echo",
    "foxtrot",
    "golf",
    "hotel",
    "india",
    "juliet",
    "kilo",
    "lima",
    "mike",
    "november",
    "oscar",
    "papa",
    "quebec",
    "romeo",
    "sierra",
    "tango",
    "uniform",
    "victor",
    "whiskey",
    "xray",
    "yankee",
    "zulu",
    "amber",
    "boulder",
    "cobalt",
    "dune",
    "ember",
    "flint",
    "granite",
    "harbor",
    "isle",
    "jade",
    "keel",
    "lagoon",
    "marble",
    "nebula",
    "onyx",
    "pearl",
    "quartz",
    "ripple",
    "sapphire",
    "timber",
    "umber",
    "vertex",
    "willow",
    "xenon",
    "yellow",
    "zephyr",
    "aurora",
    "banyan",
    "cascade",
    "drift",
    "fjord",
    "grove",
    "hollow",
    "oslo",
    "kyoto",
    "dublin",
    "vienna",
    "madrid",
    "paris",
    "berlin",
    "prague",
    "rome",
    "lisbon",
    "athens",
    "helsinki",
    "zurich",
    "warsaw",
    "riga",
    "vilnius",
    "stockholm",
    "cairo",
    "jakarta",
    "sydney",
    "moscow",
    "baku",
    "seoul",
    "delhi",
    "beijing",
    "hanoi",
    "bangkok",
    "manila",
    "doha",
    "tbilisi",
    "amsterdam",
    "brussels",
    "sofia",
    "bucharest",
    "reykjavik",
    "nairobi",
    "capetown",
    "lagos",
    "kinshasa",
    "santiago",
    "quito",
    "lima",
    "caracas",
    "bogota",
    "montevideo",
    "osaka",
    "dubai",
    "riyadh",
    "kigali",
    "accra",
    "almaty",
    "aktau",
    "astana",
    "bishkek",
    "tashkent",
    "kabul",
    "isfahan",
    "tehran",
    "newyork",
    "boston",
    "seattle",
    "miami",
    "houston",
]


async def _pull_with_auth(image: str, creds) -> None:
    """
    Если образ приватный – тянем его, передавая auth_config
    (credstore/глобальный login не нужен).
    """
    try:
        docker_client.images.pull(image, auth_config={
            "username": creds.username,
            "password": creds.token,
        })
    except docker.errors.APIError as e:
        raise HTTPException(403, f"Pull failed: {e.explanation}")


def derive_fernet_key(salt: str) -> bytes:
    """
    Из MASTER_KEY (из env) + salt строим 32-байтный ключ для Fernet.
    """
    master = os.getenv("FERNET_KEY", "").encode()
    if not master:
        raise RuntimeError("FERNET_KEY is not set")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=390_000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(master))


MAX_DB_PER_USER = os.getenv("MAX_DB_PER_USER")


def get_fernet_for_salt(salt: str) -> Fernet:
    return Fernet(derive_fernet_key(salt))


def get_fernet() -> Fernet:
    key = os.getenv("FERNET_KEY", "FERNET_KEY")
    if not key:
        raise RuntimeError("FERNET_KEY not set in env")
    return Fernet(key)


MAX_TOTAL_DB_SIZE = 500 * 1024 * 1024


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


def create_temp_docker_config(username: str, token: str):
    temp_dir = tempfile.TemporaryDirectory()
    config_path = Path(temp_dir.name) / "config.json"
    auth = base64.b64encode(f"{username}:{token}".encode()).decode()
    config_path.write_text(json.dumps({
        "auths": {
            "https://index.docker.io/v1/": {
                "auth": auth
            }
        }
    }))
    return temp_dir


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

        login_performed = False
        try:
            docker_client.images.pull(image)  # публичная картинка?
        except docker.errors.APIError as e:
            if "pull access denied" in str(e).lower():
                creds = await DockerHubCredential.get_or_none(user=user)
                if not creds:
                    raise HTTPException(403, "Private image, login required")

                await _pull_with_auth(image, creds)  # ← вставляем точечную авторизацию
            else:
                raise

        docker_client.containers.run(
            image,
            name=f"{name}_u{user.id}",
            detach=True,
            mem_limit=mem_limit,
            cpu_quota=cpu_quota,
            labels={"owner": str(user.id)},
            ports=ports_map or None,
            environment=env_map or None,
            volumes=volumes_map or None,
        )

        if login_performed:
            try:
                docker_client.logout()  # удаляет токен из ~/.docker/config.json
            except Exception as logout_error:
                logger.warning(f"Docker logout failed: {logout_error}")

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
        parsed = yaml.safe_load(content)
        if "services" in parsed:
            for svc in parsed["services"].values():
                if "container_name" in svc and isinstance(svc["container_name"], str):
                    svc["container_name"] = f"{svc['container_name']}_u{user.id}"
        content = yaml.dump(parsed)
    except Exception as e:
        return templates.TemplateResponse(
            "compose.html",
            {
                "request": request,
                "error": f"YAML processing error: {e}",
                "compose_text": content,
            },
        )
    creds = await DockerHubCredential.get_or_none(user=user)
    if creds:
        try:
            docker_client.login(username=creds.username, password=creds.token)
        except docker.errors.APIError as e:
            return templates.TemplateResponse(
                "compose.html",
                {
                    "request": request,
                    "error": f"Docker Hub login failed: {e.explanation}",
                    "compose_text": content,
                },
            )

    try:
        await api_run_compose(
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
    # one-time creation info
    new_db = request.session.pop("new_db", None)
    # any error/success messages
    db_error = request.session.pop("db_error", None)
    db_success = request.session.pop("db_success", None)

    dbs = await UserDatabase.filter(owner=user).order_by("created_at")
    count = len(dbs)

    return templates.TemplateResponse(
        "databases.html",
        {
            "request": request,
            "databases": dbs,
            "new_db": new_db,
            "db_error": db_error,
            "db_success": db_success,
            "count": count,
            "max": int(MAX_DB_PER_USER),
        },
    )


@router.post("/databases/create", response_class=HTMLResponse)
async def create_database(
        request: Request,
        name: str = Form(...),
        user: User = Depends(get_current_user),
):
    await check_access(user)

    # ограничение по количеству
    if await UserDatabase.filter(owner=user).count() >= 3:
        request.session["db_error"] = "You have reached the limit of 3 databases"
        return RedirectResponse(
            "/stacks/databases", status_code=status.HTTP_303_SEE_OTHER
        )

    # уникальный суффикс для имени
    suffix = f"_u{user.id}"
    db_name = f"{name}{suffix}"

    # генерим юзера и пароль
    db_user = f"{user.username}_{secrets.token_hex(3)}"
    raw_password = secrets.token_urlsafe(12)

    # генерим одноразовый salt
    salt = "-".join(secrets.choice(SALT_WORDS) for _ in range(3))
    f = get_fernet_for_salt(salt)
    encrypted = f.encrypt(raw_password.encode()).decode()

    # создаём в Postgres
    try:
        conn = await asyncpg.connect(
            user=os.getenv("POSTGRES_USER_USER"),
            password=os.getenv("POSTGRES_USER_PASSWORD"),
            database=os.getenv("POSTGRES_USER_DB", "postgres"),
            host=os.getenv("PGDB_USER_HOST", "pgdb_user"),
            port=int(os.getenv("PGDB_USER_PORT", 5432)),
        )
        await conn.execute(f"CREATE USER \"{db_user}\" WITH PASSWORD '{raw_password}';")
        await conn.execute(f'CREATE DATABASE "{db_name}" OWNER "{db_user}";')
        await conn.close()
    except Exception as e:
        request.session["db_error"] = f"Postgres error: {e}"
        return RedirectResponse(
            "/stacks/databases", status_code=status.HTTP_303_SEE_OTHER
        )

    # сохраняем только зашифрованный пароль
    db = await UserDatabase.create(
        name=db_name, owner=user, db_user=db_user, db_password_encrypted=encrypted
    )

    # кладём в сессию одноразово
    request.session["new_db"] = {
        "id": db.id,
        "name": db_name,
        "db_user": db_user,
        "password": raw_password,
        "salt": salt,
    }

    return RedirectResponse("/stacks/databases", status_code=status.HTTP_303_SEE_OTHER)


class RevealRequest(BaseModel):
    salt: str


@router.post("/databases/{db_id}/reveal")
async def reveal_database(
        db_id: int,
        request: Request,
        user: User = Depends(get_current_user),
):
    await check_access(user)

    # ищем запись
    db = await UserDatabase.get_or_none(id=db_id, owner=user)
    if not db:
        raise HTTPException(status_code=404, detail="Database not found")

    # достаём salt из JSON body
    payload = await request.json()
    salt = payload.get("salt", "")

    # строим тот же Fernet и дешифруем
    try:
        f = get_fernet_for_salt(salt)
        raw = f.decrypt(db.db_password_encrypted.encode()).decode()
    except Exception:
        return JSONResponse(
            {"success": False, "error": "Invalid salt or decryption failed"}
        )

    return JSONResponse({"success": True, "password": raw})


@router.post("/databases/{db_id}/delete")
async def delete_database(
        db_id: int,
        request: Request,
        user: User = Depends(get_current_user),
):
    await check_access(user)
    db = await UserDatabase.get_or_none(id=db_id, owner=user)
    if not db:
        request.session["db_error"] = "Database not found"
        return RedirectResponse(
            "/stacks/databases", status_code=status.HTTP_303_SEE_OTHER
        )

    try:
        conn = await asyncpg.connect(
            user=os.getenv("POSTGRES_USER_USER"),
            password=os.getenv("POSTGRES_USER_PASSWORD"),
            database=os.getenv("POSTGRES_USER_DB", "postgres"),
            host=os.getenv("PGDB_USER_HOST", "pgdb_user"),
            port=int(os.geenv("PGDB_USER_PORT", 5432)),
        )
        await conn.execute(f'DROP DATABASE IF EXISTS "{db.name}";')
        await conn.execute(f'DROP USER IF EXISTS "{db.db_user}";')
        await conn.close()
        await db.delete()
        request.session["db_success"] = f"Database '{db.name}' deleted."
    except Exception as e:
        request.session["db_error"] = f"Error deleting database: {e}"

    return RedirectResponse("/stacks/databases", status_code=status.HTTP_303_SEE_OTHER)


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

    creds = await DockerHubCredential.get_or_none(user=user)
    dockerhub_user = creds.username if creds else None

    return templates.TemplateResponse(
        "dockerhub_login.html",
        {
            "request": request,
            "dockerhub_user": dockerhub_user,
        },
    )


@router.post("/dockerhub")
async def dockerhub_auth_submit(
        request: Request,
        username: str = Form(...),
        token: str = Form(...),
        user: User = Depends(get_current_user),
):
    await check_access(user)

    # Просто сохраняем или обновляем креденшлы
    await DockerHubCredential.update_or_create(
        {"username": username, "token": token}, user=user
    )

    # Обновим имя в UI (необязательно)
    request.session["dockerhub_user"] = username

    return RedirectResponse("/stacks/dockerhub", status_code=303)
