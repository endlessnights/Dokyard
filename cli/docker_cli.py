import json
import os

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
    resp = httpx.post(
        f"{API_URL}/api/login", json={"username": user, "password": password}
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    save_token(token)
    typer.echo("Logged in.")


@app.command()
def ps():
    headers = {"Authorization": f"Bearer {load_token()}"}
    resp = httpx.get(f"{API_URL}/containers/", headers=headers, follow_redirects=True)
    resp.raise_for_status()
    for ctr in resp.json():
        typer.echo(f"{ctr['id'][:12]}  {ctr['name']}  {ctr['status']}")


@app.command()
def run(image: str, name: str, mem: str = "512m", cpu: int = 50000):
    headers = {"Authorization": f"Bearer {load_token()}"}
    spec = {"image": image, "name": name, "mem_limit": mem, "cpu_quota": cpu}
    resp = httpx.post(f"{API_URL}/containers/run", json=spec, headers=headers, timeout=180, follow_redirects=True)
    typer.echo(resp.json())


@app.command()
def rm(ctr_id: str):
    headers = {"Authorization": f"Bearer {load_token()}"}
    resp = httpx.delete(f"{API_URL}/containers/{ctr_id}", headers=headers, follow_redirects=True)
    typer.echo(resp.json())


if __name__ == "__main__":
    app()
