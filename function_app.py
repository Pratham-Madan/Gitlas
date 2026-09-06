import base64
import json
import os
import time

import azure.functions as func
import jwt
import requests


app = func.FunctionApp(
    http_auth_level=func.AuthLevel.FUNCTION
)


# ============================================================
# GitHub Authentication
# ============================================================

def create_github_app_jwt() -> str:
    """
    Creates a short-lived JWT for authenticating
    as the GitHub App.
    """

    app_id = os.environ["GITHUB_APP_ID"]
    private_key = os.environ["GITHUB_PRIVATE_KEY"]

    now = int(time.time())

    payload = {
        "iat": now - 60,
        "exp": now + (9 * 60),
        "iss": app_id,
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
    )


def get_installation_token() -> str:
    """
    Gets a temporary installation access token
    for the GitHub App installation.
    """

    installation_id = os.environ[
        "GITHUB_INSTALLATION_ID"
    ]

    app_jwt = create_github_app_jwt()

    url = (
        "https://api.github.com/app/installations/"
        f"{installation_id}/access_tokens"
    )

    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    response = requests.post(
        url,
        headers=headers,
        timeout=30,
    )

    if not response.ok:
        raise Exception(
            "GitHub installation token request failed: "
            f"{response.status_code} - {response.text}"
        )

    return response.json()["token"]


def get_github_headers() -> dict:
    """
    Returns authenticated headers for GitHub API requests.
    """

    installation_token = get_installation_token()

    return {
        "Authorization": (
            f"Bearer {installation_token}"
        ),
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# ============================================================
# Health Check
# ============================================================

@app.route(
    route="health",
    methods=["GET"],
)
def health(
    req: func.HttpRequest,
) -> func.HttpResponse:

    return func.HttpResponse(
        json.dumps({
            "status": "healthy"
        }),
        status_code=200,
        mimetype="application/json",
    )


# ============================================================
# Get All Accessible GitHub Repositories
# ============================================================
@app.route(
    route="deployment-test",
    methods=["GET"],
)
def deployment_test(
    req: func.HttpRequest,
) -> func.HttpResponse:

    return func.HttpResponse(
        json.dumps({
            "status": "deployment successful",
            "message": "GitHub Actions deployment is working"
        }),
        status_code=200,
        mimetype="application/json",
    )
@app.route(
    route="github/repositories",
    methods=["GET"],
)
def github_repositories(
    req: func.HttpRequest,
) -> func.HttpResponse:

    try:
        headers = get_github_headers()

        response = requests.get(
            "https://api.github.com/installation/repositories",
            headers=headers,
            timeout=30,
        )

        if not response.ok:
            return func.HttpResponse(
                json.dumps({
                    "connected": False,
                    "error": (
                        "GitHub repository request failed: "
                        f"{response.status_code} - "
                        f"{response.text}"
                    ),
                }),
                status_code=500,
                mimetype="application/json",
            )

        data = response.json()

        repositories = [
            {
                "id": repo.get("id"),
                "name": repo.get("name"),
                "full_name": repo.get("full_name"),
                "private": repo.get("private"),
                "html_url": repo.get("html_url"),
                "description": repo.get("description"),
            }
            for repo in data.get("repositories", [])
        ]

        return func.HttpResponse(
            json.dumps({
                "connected": True,
                "repository_count": len(repositories),
                "repositories": repositories,
            }),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as exc:

        return func.HttpResponse(
            json.dumps({
                "connected": False,
                "error": str(exc),
            }),
            status_code=500,
            mimetype="application/json",
        )


# ============================================================
# Get Detailed Repository Information
# ============================================================

@app.route(
    route="github/repository/{owner}/{repo}",
    methods=["GET"],
)
def github_repository_details(
    req: func.HttpRequest,
) -> func.HttpResponse:

    owner = req.route_params.get("owner")
    repo = req.route_params.get("repo")

    if not owner or not repo:
        return func.HttpResponse(
            json.dumps({
                "error": "Owner and repository name are required."
            }),
            status_code=400,
            mimetype="application/json",
        )

    try:

        headers = get_github_headers()

        # ----------------------------------------------------
        # 1. Repository information
        # ----------------------------------------------------

        repo_url = (
            f"https://api.github.com/repos/"
            f"{owner}/{repo}"
        )

        repo_response = requests.get(
            repo_url,
            headers=headers,
            timeout=30,
        )

        if not repo_response.ok:
            return func.HttpResponse(
                json.dumps({
                    "error": "Unable to retrieve repository.",
                    "status_code": (
                        repo_response.status_code
                    ),
                    "details": repo_response.text,
                }),
                status_code=500,
                mimetype="application/json",
            )

        repository = repo_response.json()

        default_branch = repository.get(
            "default_branch"
        )

        # ----------------------------------------------------
        # 2. Repository file tree
        # ----------------------------------------------------

        files = []

        if default_branch:

            tree_url = (
                f"https://api.github.com/repos/"
                f"{owner}/{repo}/git/trees/"
                f"{default_branch}?recursive=1"
            )

            tree_response = requests.get(
                tree_url,
                headers=headers,
                timeout=30,
            )

            if tree_response.ok:

                tree_data = tree_response.json()

                files = [
                    {
                        "path": item.get("path"),
                        "type": item.get("type"),
                        "size": item.get("size"),
                    }
                    for item in tree_data.get(
                        "tree",
                        []
                    )
                    if item.get("type") == "blob"
                ]

        # ----------------------------------------------------
        # 3. README
        # ----------------------------------------------------

        readme_content = None
        readme_name = None

        readme_url = (
            f"https://api.github.com/repos/"
            f"{owner}/{repo}/readme"
        )

        readme_response = requests.get(
            readme_url,
            headers=headers,
            timeout=30,
        )

        if readme_response.ok:

            readme_data = readme_response.json()

            readme_name = readme_data.get(
                "name"
            )

            encoded_content = readme_data.get(
                "content"
            )

            if encoded_content:

                try:

                    readme_content = (
                        base64.b64decode(
                            encoded_content
                        )
                        .decode(
                            "utf-8",
                            errors="replace",
                        )
                    )

                except Exception:
                    readme_content = None

        # ----------------------------------------------------
        # 4. Detect important project files
        # ----------------------------------------------------

        file_paths = [
            file["path"]
            for file in files
            if file.get("path")
        ]

        project_files = {
            "readme": [],
            "python": [],
            "javascript": [],
            "typescript": [],
            "dotnet": [],
            "java": [],
            "database": [],
            "docker": [],
            "configuration": [],
        }

        for path in file_paths:

            lower_path = path.lower()

            # README
            if lower_path.startswith("readme"):
                project_files["readme"].append(path)

            # Python
            if (
                lower_path.endswith(".py")
                or lower_path == "requirements.txt"
                or lower_path == "pyproject.toml"
            ):
                project_files["python"].append(path)

            # JavaScript
            if (
                lower_path.endswith(".js")
                or lower_path == "package.json"
                or lower_path == "package-lock.json"
            ):
                project_files["javascript"].append(path)

            # TypeScript
            if (
                lower_path.endswith(".ts")
                or lower_path.endswith(".tsx")
            ):
                project_files["typescript"].append(path)

            # .NET
            if (
                lower_path.endswith(".cs")
                or lower_path.endswith(".csproj")
                or lower_path.endswith(".sln")
            ):
                project_files["dotnet"].append(path)

            # Java
            if (
                lower_path.endswith(".java")
                or lower_path == "pom.xml"
                or lower_path == "build.gradle"
            ):
                project_files["java"].append(path)

            # Database
            if (
                lower_path.endswith(".sql")
                or "migration" in lower_path
            ):
                project_files["database"].append(path)

            # Docker
            if (
                "dockerfile" in lower_path
                or "docker-compose" in lower_path
            ):
                project_files["docker"].append(path)

            # Configuration
            if (
                lower_path.endswith(".json")
                or lower_path.endswith(".yaml")
                or lower_path.endswith(".yml")
                or lower_path.endswith(".xml")
            ):
                project_files[
                    "configuration"
                ].append(path)

        # ----------------------------------------------------
        # 5. Build final response
        # ----------------------------------------------------

        result = {

            "repository": {

                "id": repository.get("id"),

                "name": repository.get(
                    "name"
                ),

                "full_name": repository.get(
                    "full_name"
                ),

                "description": repository.get(
                    "description"
                ),

                "private": repository.get(
                    "private"
                ),

                "url": repository.get(
                    "html_url"
                ),

                "default_branch": default_branch,

                "language": repository.get(
                    "language"
                ),

                "stars": repository.get(
                    "stargazers_count"
                ),

                "forks": repository.get(
                    "forks_count"
                ),

                "watchers": repository.get(
                    "watchers_count"
                ),

                "topics": repository.get(
                    "topics",
                    []
                ),

                "created_at": repository.get(
                    "created_at"
                ),

                "updated_at": repository.get(
                    "updated_at"
                ),

                "owner": repository.get(
                    "owner",
                    {}
                ).get(
                    "login"
                ),
            },

            "readme": {

                "name": readme_name,

                "available": (
                    readme_content is not None
                ),

                "content": readme_content,
            },

            "files": files,

            "file_count": len(files),

            "project_files": project_files,
        }

        return func.HttpResponse(
            json.dumps(
                result,
                indent=2,
            ),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as exc:

        return func.HttpResponse(
            json.dumps({
                "error": str(exc),
            }),
            status_code=500,
            mimetype="application/json",
        )
