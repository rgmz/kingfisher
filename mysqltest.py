#!/usr/bin/env python3
"""Start a MySQL 8.4 Docker container with a known root password.

The script ensures the container keeps running and writes the connection
string to /tmp/mysql-creds.log for convenience.
"""
import subprocess
import sys
import time
from pathlib import Path

IMAGE = "mysql:8.4"
CONTAINER_NAME = "kingfisher-mysql"
ROOT_PASSWORD = "superman123"
HOST = "127.0.0.1"
PORT = 3306
CREDS_PATH = Path("/tmp/mysql-creds.log")
READY_TIMEOUT = 120


def run(cmd, check=True, capture_output=False, text=True):
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=text)


def container_exists(name: str) -> bool:
    result = run([
        "docker",
        "ps",
        "-aq",
        "--filter",
        f"name=^{name}$",
    ], capture_output=True)
    return bool(result.stdout.strip())


def remove_container(name: str) -> None:
    if container_exists(name):
        run(["docker", "rm", "-f", name])


def pull_image() -> None:
    run(["docker", "pull", IMAGE])


def start_container() -> None:
    run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            CONTAINER_NAME,
            "-e",
            f"MYSQL_ROOT_PASSWORD={ROOT_PASSWORD}",
            "-p",
            f"{PORT}:3306",
            IMAGE,
        ]
    )


def wait_for_mysql() -> None:
    start = time.time()
    while time.time() - start < READY_TIMEOUT:
        try:
            run(
                [
                    "docker",
                    "exec",
                    CONTAINER_NAME,
                    "mysqladmin",
                    "ping",
                    "-h",
                    "127.0.0.1",
                    "-uroot",
                    f"-p{ROOT_PASSWORD}",
                ]
            )
            return
        except subprocess.CalledProcessError:
            time.sleep(2)
    raise RuntimeError("MySQL container did not become ready in time")


def write_creds_file() -> None:
    conn = f"mysql://root:{ROOT_PASSWORD}@{HOST}:{PORT}/"
    CREDS_PATH.write_text(conn + "\n", encoding="utf-8")
    print(f"Wrote connection string to {CREDS_PATH}: {conn}")


def main() -> None:
    try:
        pull_image()
        remove_container(CONTAINER_NAME)
        start_container()
        wait_for_mysql()
        write_creds_file()
        print(
            "MySQL container is running. Use `docker logs -f %s` to monitor it." % CONTAINER_NAME
        )
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to start MySQL container: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()