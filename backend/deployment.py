from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import subprocess
import os
import re


def require_local_deployment():
    if os.getenv("CLOUDGUARD_ENABLE_DEPLOYMENT") != "1":
        raise HTTPException(403, "Local Docker execution is disabled. Enable only in a trusted, isolated development environment.")


router = APIRouter(
    prefix="/deployment",
    tags=["Deployment"],
    dependencies=[Depends(require_local_deployment)]
)


# --------------------------------------------------
# REQUEST MODELS
# --------------------------------------------------

class BuildRequest(BaseModel):
    repo_path: str


class DeployRequest(BaseModel):
    repo_path: str
    host_port: int = 8080
    container_port: int = 8000


# --------------------------------------------------
# HELPER - CREATE SAFE DOCKER NAME
# --------------------------------------------------

def create_safe_name(repo_path):
    repo_name = os.path.basename(
        os.path.normpath(repo_path)
    )

    safe_name = re.sub(
        r"[^a-zA-Z0-9_.-]",
        "-",
        repo_name
    ).lower()

    return safe_name


# --------------------------------------------------
# CHECK DOCKER
# --------------------------------------------------

@router.get("/docker-status")
def docker_status():

    try:

        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                "status": "UNAVAILABLE",
                "message": "Docker is not available.",
                "error": result.stderr
            }

        return {
            "status": "AVAILABLE",
            "message": "Docker is installed.",
            "docker_version": result.stdout.strip()
        }

    except FileNotFoundError:

        return {
            "status": "UNAVAILABLE",
            "message": "Docker command was not found."
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "message": str(error)
        }


# --------------------------------------------------
# BUILD DOCKER IMAGE
# --------------------------------------------------

@router.post("/build")
def build_docker_image(request: BuildRequest):

    repo_path = os.path.abspath(
        request.repo_path
    )

    # ----------------------------------------------
    # CHECK REPOSITORY
    # ----------------------------------------------

    if not os.path.isdir(repo_path):

        raise HTTPException(
            status_code=404,
            detail="Repository folder does not exist."
        )

    # ----------------------------------------------
    # CHECK DOCKERFILE
    # ----------------------------------------------

    dockerfile_path = os.path.join(
        repo_path,
        "Dockerfile"
    )

    if not os.path.isfile(dockerfile_path):

        raise HTTPException(
            status_code=400,
            detail="Dockerfile was not found in repository root."
        )

    # ----------------------------------------------
    # IMAGE NAME
    # ----------------------------------------------

    repo_name = create_safe_name(repo_path)

    image_name = f"cloudgaurd-{repo_name}:latest"

    # ----------------------------------------------
    # BUILD IMAGE
    # ----------------------------------------------

    try:

        result = subprocess.run(
            [
                "docker",
                "build",
                "-t",
                image_name,
                "."
            ],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=600
        )

    except FileNotFoundError:

        raise HTTPException(
            status_code=500,
            detail=(
                "Docker command was not found. "
                "Make sure Docker Desktop is installed."
            )
        )

    except subprocess.TimeoutExpired:

        raise HTTPException(
            status_code=408,
            detail="Docker image build timed out."
        )

    # ----------------------------------------------
    # BUILD FAILED
    # ----------------------------------------------

    if result.returncode != 0:

        return {
            "status": "FAILED",
            "message": "Docker image build failed.",
            "image_name": image_name,
            "error": result.stderr,
            "logs": result.stdout
        }

    # ----------------------------------------------
    # BUILD SUCCESS
    # ----------------------------------------------

    return {
        "status": "SUCCESS",
        "message": "Docker image built successfully.",
        "image_name": image_name,
        "logs": result.stdout
    }


# --------------------------------------------------
# DEPLOY / RUN DOCKER CONTAINER
# --------------------------------------------------

@router.post("/deploy")
def deploy_container(request: DeployRequest):

    repo_path = os.path.abspath(
        request.repo_path
    )

    if not os.path.isdir(repo_path):

        raise HTTPException(
            status_code=404,
            detail="Repository folder does not exist."
        )

    repo_name = create_safe_name(repo_path)

    image_name = f"cloudgaurd-{repo_name}:latest"

    container_name = f"cloudgaurd-{repo_name}"

    # ----------------------------------------------
    # CHECK IMAGE EXISTS
    # ----------------------------------------------

    image_check = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            image_name
        ],
        capture_output=True,
        text=True
    )

    if image_check.returncode != 0:

        raise HTTPException(
            status_code=400,
            detail=(
                "Docker image does not exist. "
                "Build the image before deployment."
            )
        )

    # ----------------------------------------------
    # REMOVE OLD CONTAINER
    # ----------------------------------------------

    subprocess.run(
        [
            "docker",
            "rm",
            "-f",
            container_name
        ],
        capture_output=True,
        text=True
    )

    # ----------------------------------------------
    # START NEW CONTAINER
    # ----------------------------------------------

    try:

        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "-p",
                f"{request.host_port}:{request.container_port}",
                image_name
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

    except subprocess.TimeoutExpired:

        raise HTTPException(
            status_code=408,
            detail="Container deployment timed out."
        )

    # ----------------------------------------------
    # DEPLOYMENT FAILED
    # ----------------------------------------------

    if result.returncode != 0:

        return {
            "status": "FAILED",
            "message": "Container deployment failed.",
            "image_name": image_name,
            "container_name": container_name,
            "error": result.stderr
        }

    # ----------------------------------------------
    # DEPLOYMENT SUCCESS
    # ----------------------------------------------

    container_id = result.stdout.strip()

    return {
        "status": "SUCCESS",
        "message": "Application deployed successfully.",
        "image_name": image_name,
        "container_name": container_name,
        "container_id": container_id,
        "host_port": request.host_port,
        "container_port": request.container_port,
        "application_url": (
            f"http://localhost:{request.host_port}"
        )
    }


# --------------------------------------------------
# STOP DEPLOYMENT
# --------------------------------------------------

@router.delete("/stop/{container_name}")
def stop_container(container_name: str):

    result = subprocess.run(
        [
            "docker",
            "rm",
            "-f",
            container_name
        ],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:

        raise HTTPException(
            status_code=400,
            detail=result.stderr
        )

    return {
        "status": "SUCCESS",
        "message": "Deployment stopped.",
        "container_name": container_name
    }
