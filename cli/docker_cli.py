import os
from typing import List

import httpx
import typer

app = typer.Typer()
API_URL = os.environ.get("DOCKER_PROXY_URL", "http://localhost:8000")
TOKEN_FILE = os.path.expanduser("~/.docker_proxy_token")


def save_token(token: str):
    with open(TOKEN_FILE, "w") as f:
        f.write(token)


def load_token() -> str:
    return open(TOKEN_FILE).read().strip()


@app.command()
def login(user: str, password: str):
    resp = httpx.post(f"{API_URL}/api/login", json={"username": user, "password": password})
    resp.raise_for_status()
    save_token(resp.json()["access_token"])
    typer.echo("Logged in.")


@app.command()
def ps():
    headers = {"Authorization": f"Bearer {load_token()}"}
    resp = httpx.get(f"{API_URL}/containers/", headers=headers, follow_redirects=True)
    resp.raise_for_status()
    for c in resp.json():
        typer.echo(f"{c['id'][:12]}  {c['name']}  {c['status']}")


@app.command()
def run(
    image: str,
    name: str,
    mem: str = "512m",
    cpu: int = 50000,
    volumes: List[str] = typer.Option(
        None, "--volume", "-v", help="host_path:container_path[:mode]"
    ),
):
    headers = {"Authorization": f"Bearer {load_token()}"}
    spec = {"image": image, "name": name, "mem_limit": mem, "cpu_quota": cpu}
    if volumes:
        spec["volumes"] = volumes
    resp = httpx.post(f"{API_URL}/containers/run", json=spec, headers=headers,
                      timeout=180, follow_redirects=True)
    if resp.status_code >= 400:
        typer.secho(f"Error {resp.status_code}:\n{resp.text}", fg="red")
        raise typer.Exit(1)
    typer.echo(resp.json())


@app.command()
def start(ctr_id: str):
    """Запустить остановленный контейнер."""
    headers = {"Authorization": f"Bearer {load_token()}"}
    resp = httpx.post(f"{API_URL}/containers/{ctr_id}/start", headers=headers)
    if resp.status_code >= 400:
        typer.secho(f"Error {resp.status_code}:\n{resp.text}", fg="red")
        raise typer.Exit(1)
    typer.echo(resp.json())


@app.command()
def stop(ctr_id: str):
    """Остановить работающий контейнер."""
    headers = {"Authorization": f"Bearer {load_token()}"}
    resp = httpx.post(f"{API_URL}/containers/{ctr_id}/stop", headers=headers)
    if resp.status_code >= 400:
        typer.secho(f"Error {resp.status_code}:\n{resp.text}", fg="red")
        raise typer.Exit(1)
    typer.echo(resp.json())


@app.command()
def rm(ctr_id: str):
    """Удалить контейнер."""
    headers = {"Authorization": f"Bearer {load_token()}"}
    resp = httpx.delete(f"{API_URL}/containers/{ctr_id}", headers=headers, follow_redirects=True)
    typer.echo(resp.json())


@app.command()
def images():
    """Показать список образов текущего пользователя."""
    headers = {"Authorization": f"Bearer {load_token()}"}
    resp = httpx.get(f"{API_URL}/containers/images", headers=headers)
    resp.raise_for_status()
    for img in resp.json():
        typer.echo(f"{img['id'][:12]}  {img['tags']}")


@app.command()
def rmi(image_id: str):
    """Удалить образ (если все контейнеры на его основе остановлены)."""
    headers = {"Authorization": f"Bearer {load_token()}"}
    resp = httpx.delete(f"{API_URL}/containers/images/{image_id}", headers=headers)
    if resp.status_code >= 400:
        typer.secho(f"Error {resp.status_code}:\n{resp.text}", fg="red")
        raise typer.Exit(1)
    typer.echo(resp.json())


@app.command()
def compose(file: str):
    """Запустить docker-compose из файла."""
    headers = {"Authorization": f"Bearer {load_token()}"}
    yaml_text = open(file, "r", encoding="utf-8").read()
    resp = httpx.post(f"{API_URL}/containers/compose", json={"compose_yaml": yaml_text},
                      headers=headers, timeout=None)
    if resp.status_code >= 400:
        typer.secho(f"Error {resp.status_code}:\n{resp.text}", fg="red")
        raise typer.Exit(1)
    data = resp.json()
    typer.echo("Created containers:")
    for c in data["containers"]:
        typer.echo(f"  {c['service']}: {c['id'][:12]}")


if __name__ == "__main__":
    app()
