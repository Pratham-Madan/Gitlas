import base64
import json
import os
import re
import time

from azure.identity import ManagedIdentityCredential
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
# Azure DevOps Authentication
# ============================================================

def get_azure_devops_token() -> str:

    credential = ManagedIdentityCredential()

    token = credential.get_token(
        "499b84ac-1321-427f-aa17-267ca6975798/.default"
    )

    return token.token


def get_azure_devops_headers() -> dict:

    return {
        "Authorization": (
            f"Bearer {get_azure_devops_token()}"
        ),
        "Content-Type": "application/json",
    }
# ============================================================
# Metadata Extraction Helpers
# ============================================================

def contains_any(text: str, keywords: list[str]) -> bool:
    """
    Returns True if any keyword exists in the supplied text.
    Case-insensitive.
    """

    text = text.lower()

    return any(
        keyword.lower() in text
        for keyword in keywords
    )


def unique_values(values: list[str]) -> list[str]:
    """
    Removes duplicates while preserving order.
    """

    result = []

    for value in values:
        if value and value not in result:
            result.append(value)

    return result


def detect_programming_languages(
    repository_language: str | None,
    project_files: dict,
) -> list[str]:

    languages = []

    if repository_language:
        languages.append(repository_language)

    if project_files.get("python"):
        languages.append("Python")

    if project_files.get("javascript"):
        languages.append("JavaScript")

    if project_files.get("typescript"):
        languages.append("TypeScript")

    if project_files.get("dotnet"):
        languages.append("C#")

    if project_files.get("java"):
        languages.append("Java")

    return unique_values(languages)


def detect_technologies(
    file_paths: list[str],
    readme: str,
    repository_language: str | None,
) -> list[str]:

    technologies = []

    text = readme.lower()
    paths = " ".join(file_paths).lower()

    if repository_language:
        technologies.append(repository_language)

    if ".py" in paths or "requirements.txt" in paths:
        technologies.append("Python")

    if ".js" in paths or "package.json" in paths:
        technologies.append("JavaScript")

    if ".ts" in paths or ".tsx" in paths:
        technologies.append("TypeScript")

    if ".cs" in paths or ".csproj" in paths:
        technologies.append(".NET")

    if ".java" in paths or "pom.xml" in paths:
        technologies.append("Java")

    if "react" in text or "react" in paths:
        technologies.append("React")

    if "angular" in text or "angular" in paths:
        technologies.append("Angular")

    if "vue" in text or "vue" in paths:
        technologies.append("Vue.js")

    if "node.js" in text or "nodejs" in text:
        technologies.append("Node.js")

    if "python" in text:
        technologies.append("Python")

    if "docker" in text or "dockerfile" in paths:
        technologies.append("Docker")

    if "kubernetes" in text or "k8s" in text:
        technologies.append("Kubernetes")

    if "terraform" in text or ".tf" in paths:
        technologies.append("Terraform")

    return unique_values(technologies)


def detect_frameworks(
    file_paths: list[str],
    readme: str,
) -> list[str]:

    frameworks = []

    text = readme.lower()
    paths = " ".join(file_paths).lower()

    framework_rules = {
        "FastAPI": [
            "fastapi",
        ],
        "Flask": [
            "flask",
        ],
        "Django": [
            "django",
        ],
        "React": [
            "react",
            "next.js",
            "nextjs",
        ],
        "Angular": [
            "angular",
        ],
        "Vue.js": [
            "vue",
        ],
        "ASP.NET Core": [
            "asp.net",
            "aspnet",
            "microsoft.aspnetcore",
        ],
        "Spring Boot": [
            "spring boot",
            "spring-boot",
        ],
        "Express.js": [
            "express",
        ],
    }

    combined_text = f"{text} {paths}"

    for framework, keywords in framework_rules.items():

        if contains_any(combined_text, keywords):
            frameworks.append(framework)

    return unique_values(frameworks)


def detect_cloud(
    readme: str,
    file_paths: list[str],
) -> list[str]:

    clouds = []

    text = readme.lower()
    paths = " ".join(file_paths).lower()

    combined_text = f"{text} {paths}"

    cloud_rules = {
        "Azure": [
            "azure",
            "microsoft azure",
            "azure functions",
            "azure sql",
            "azure storage",
        ],
        "AWS": [
            "aws",
            "amazon web services",
            "lambda",
            "s3",
            "ec2",
            "dynamodb",
        ],
        "Google Cloud": [
            "google cloud",
            "gcp",
            "cloud run",
            "cloud functions",
            "bigquery",
        ],
    }

    for cloud, keywords in cloud_rules.items():

        if contains_any(combined_text, keywords):
            clouds.append(cloud)

    return unique_values(clouds)


def detect_databases(
    readme: str,
    file_paths: list[str],
) -> list[str]:

    databases = []

    text = readme.lower()
    paths = " ".join(file_paths).lower()

    combined_text = f"{text} {paths}"

    database_rules = {
        "SQL Server": [
            "sql server",
            "mssql",
            "sqlserver",
        ],
        "Azure SQL": [
            "azure sql",
        ],
        "PostgreSQL": [
            "postgresql",
            "postgres",
        ],
        "MySQL": [
            "mysql",
        ],
        "SQLite": [
            "sqlite",
        ],
        "MongoDB": [
            "mongodb",
            "mongo",
        ],
        "Cosmos DB": [
            "cosmos db",
            "cosmosdb",
        ],
        "Redis": [
            "redis",
        ],
    }

    for database, keywords in database_rules.items():

        if contains_any(combined_text, keywords):
            databases.append(database)

    return unique_values(databases)


def detect_domain(readme: str) -> str | None:

    text = readme.lower()

    domain_rules = {
        "Authentication & Security": [
            "authentication",
            "authorization",
            "login",
            "identity",
            "oauth",
            "jwt",
        ],
        "Finance": [
            "finance",
            "financial",
            "billing",
            "invoice",
            "payment",
        ],
        "Healthcare": [
            "healthcare",
            "medical",
            "hospital",
            "patient",
        ],
        "Human Resources": [
            "hrms",
            "human resources",
            "employee management",
            "recruitment",
            "payroll",
        ],
        "E-commerce": [
            "e-commerce",
            "ecommerce",
            "shopping cart",
            "product catalog",
            "order management",
        ],
        "Education": [
            "education",
            "student management",
            "learning management",
            "course management",
        ],
        "CRM": [
            "crm",
            "customer relationship",
            "customer management",
        ],
    }

    for domain, keywords in domain_rules.items():

        if contains_any(text, keywords):
            return domain

    return None


def detect_use_case(readme: str) -> str | None:

    if not readme:
        return None

    # Remove common Markdown formatting.
    cleaned = re.sub(
        r"[#>*`]",
        "",
        readme,
    )

    lines = [
        line.strip()
        for line in cleaned.splitlines()
        if line.strip()
    ]

    if not lines:
        return None

    # Look for explicit purpose/use-case sections.
    use_case_headers = [
        "purpose",
        "use case",
        "use-case",
        "overview",
        "about",
        "description",
    ]

    for index, line in enumerate(lines):

        lower_line = line.lower().rstrip(":")

        if lower_line in use_case_headers:

            for next_line in lines[index + 1:]:
                if len(next_line) > 30:
                    return next_line[:1000]

    # Fall back to the first meaningful README paragraph.
    for line in lines:

        lower_line = line.lower()

        if (
            len(line) > 40
            and not lower_line.startswith(
                (
                    "installation",
                    "requirements",
                    "usage",
                    "features",
                    "setup",
                    "getting started",
                )
            )
        ):
            return line[:1000]

    return None


def detect_architecture(
    readme: str,
    file_paths: list[str],
) -> list[str]:

    architecture = []

    text = readme.lower()
    paths = " ".join(file_paths).lower()

    combined_text = f"{text} {paths}"

    architecture_rules = {
        "REST API": [
            "rest api",
            "restful",
            "rest endpoint",
            "api endpoint",
        ],
        "Microservices": [
            "microservices",
            "microservice",
        ],
        "Serverless": [
            "serverless",
            "azure functions",
            "aws lambda",
            "cloud functions",
        ],
        "MVC": [
            "mvc",
            "model view controller",
        ],
        "Event-Driven": [
            "event-driven",
            "event driven",
            "message queue",
            "event bus",
        ],
        "Monolithic": [
            "monolith",
            "monolithic",
        ],
    }

    for architecture_name, keywords in architecture_rules.items():

        if contains_any(combined_text, keywords):
            architecture.append(architecture_name)

    return unique_values(architecture)


def generate_summary(
    description: str | None,
    readme: str | None,
) -> str | None:

    if description:
        return description

    if not readme:
        return None

    cleaned = re.sub(
        r"[#>*`]",
        "",
        readme,
    )

    lines = [
        line.strip()
        for line in cleaned.splitlines()
        if line.strip()
    ]

    for line in lines:

        if len(line) >= 40:
            return line[:1000]

    return None


def extract_poc_metadata(
    repository: dict,
    readme: str | None,
    file_paths: list[str],
    project_files: dict,
) -> dict:

    readme_text = readme or ""

    programming_languages = (
        detect_programming_languages(
            repository.get("language"),
            project_files,
        )
    )

    technologies = detect_technologies(
        file_paths,
        readme_text,
        repository.get("language"),
    )

    frameworks = detect_frameworks(
        file_paths,
        readme_text,
    )

    cloud = detect_cloud(
        readme_text,
        file_paths,
    )

    databases = detect_databases(
        readme_text,
        file_paths,
    )

    domain = detect_domain(
        readme_text,
    )

    use_case = detect_use_case(
        readme_text,
    )

    architecture = detect_architecture(
        readme_text,
        file_paths,
    )

    return {
        "Technology": technologies,
        "Framework": frameworks,
        "Cloud": cloud,
        "DatabaseType": databases,
        "ProgrammingLanguage": programming_languages,
        "Domain": domain,
        "UseCase": use_case,
        "Architecture": architecture,
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
# Deployment Test
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


# ============================================================
# Get All Accessible GitHub Repositories
# ============================================================

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

        # ====================================================
        # 1. Find repository through the GitHub App installation
        # ====================================================

        repositories_response = requests.get(
            "https://api.github.com/installation/repositories",
            headers=headers,
            params={
                "per_page": 100,
                "page": 1,
            },
            timeout=30,
        )

        if not repositories_response.ok:
            return func.HttpResponse(
                json.dumps({
                    "error": "Unable to retrieve installed repositories.",
                    "status_code": repositories_response.status_code,
                    "details": repositories_response.text,
                }),
                status_code=500,
                mimetype="application/json",
            )

        repositories_data = repositories_response.json()

        target_full_name = f"{owner}/{repo}".lower()

        repository = None

        for candidate in repositories_data.get(
            "repositories",
            []
        ):

            if (
                candidate.get("full_name", "").lower()
                == target_full_name
            ):
                repository = candidate
                break

        if repository is None:
            return func.HttpResponse(
                json.dumps({
                    "error": "Repository is not accessible through the GitHub App installation.",
                    "requested_repository": (
                        f"{owner}/{repo}"
                    ),
                    "available_repositories": [
                        r.get("full_name")
                        for r in repositories_data.get(
                            "repositories",
                            []
                        )
                    ],
                }),
                status_code=404,
                mimetype="application/json",
            )

        # ====================================================
        # 2. Get repository details
        # ====================================================

        default_branch = repository.get(
            "default_branch"
        )

        # ====================================================
        # 3. Get repository file tree
        # ====================================================

        files = []

        if default_branch:

            tree_url = (
                f"https://api.github.com/repos/"
                f"{owner}/{repo}/git/trees/"
                f"{default_branch}"
            )

            tree_response = requests.get(
                tree_url,
                headers=headers,
                params={
                    "recursive": "1"
                },
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

        # ====================================================
        # 4. Get README
        # ====================================================

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

        # ====================================================
        # 5. Detect project files
        # ====================================================

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

            if lower_path.startswith("readme"):
                project_files["readme"].append(path)

            if (
                lower_path.endswith(".py")
                or lower_path == "requirements.txt"
                or lower_path == "pyproject.toml"
            ):
                project_files["python"].append(path)

            if (
                lower_path.endswith(".js")
                or lower_path == "package.json"
                or lower_path == "package-lock.json"
            ):
                project_files["javascript"].append(path)

            if (
                lower_path.endswith(".ts")
                or lower_path.endswith(".tsx")
            ):
                project_files["typescript"].append(path)

            if (
                lower_path.endswith(".cs")
                or lower_path.endswith(".csproj")
                or lower_path.endswith(".sln")
            ):
                project_files["dotnet"].append(path)

            if (
                lower_path.endswith(".java")
                or lower_path == "pom.xml"
                or lower_path == "build.gradle"
            ):
                project_files["java"].append(path)

            if (
                lower_path.endswith(".sql")
                or "migration" in lower_path
            ):
                project_files["database"].append(path)

            if (
                "dockerfile" in lower_path
                or "docker-compose" in lower_path
            ):
                project_files["docker"].append(path)

            if (
                lower_path.endswith(".json")
                or lower_path.endswith(".yaml")
                or lower_path.endswith(".yml")
                or lower_path.endswith(".xml")
            ):
                project_files[
                    "configuration"
                ].append(path)

        # ====================================================
        # 6. Extract POC metadata
        # ====================================================

        poc_metadata = extract_poc_metadata(
            repository=repository,
            readme=readme_content,
            file_paths=file_paths,
            project_files=project_files,
        )

        # ====================================================
        # 7. Build POC object
        # ====================================================

        poc = {

            "POCId": None,

            "Name": repository.get(
                "name"
            ),

            "Description": repository.get(
                "description"
            ),

            "Summary": generate_summary(
                repository.get("description"),
                readme_content,
            ),

            "SourceType": "GitHub",

            "SourceId": str(
                repository.get("id")
            ),

            "RepositoryUrl": repository.get(
                "html_url"
            ),

            "Owner": repository.get(
                "owner",
                {}
            ).get(
                "login"
            ),

            "CreatedDate": repository.get(
                "created_at"
            ),

            "ModifiedDate": repository.get(
                "updated_at"
            ),
        }

        # ====================================================
        # 8. Final response
        # ====================================================

        result = {

            "poc": poc,

            "POCMetadata": poc_metadata,

            "repository": {

                "id": repository.get(
                    "id"
                ),

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

# ============================================================
# Azure DevOps Projects
# ============================================================

@app.route(
    route="azuredevops/projects",
    methods=["GET"],
)
def azure_devops_projects(
    req: func.HttpRequest,
) -> func.HttpResponse:

    try:

        response = requests.get(
            "https://dev.azure.com/Gitlas-poc/_apis/projects?api-version=7.1",
            headers=get_azure_devops_headers(),
            timeout=30,
        )

        return func.HttpResponse(
            response.text,
            status_code=response.status_code,
            mimetype="application/json",
        )

    except Exception as exc:

        return func.HttpResponse(
            json.dumps({
                "error": str(exc)
            }),
            status_code=500,
            mimetype="application/json",
        )
@app.route(
    route="azuredevops/repositories",
    methods=["GET"],
)
def azure_devops_repositories(req: func.HttpRequest) -> func.HttpResponse:
    try:
        response = requests.get(
            "https://dev.azure.com/Gitlas-poc/Gitlas/_apis/git/repositories?api-version=7.1",
            headers=get_azure_devops_headers(),
            timeout=30,
        )

        if not response.ok:
            return func.HttpResponse(
                json.dumps(
                    {
                        "connected": False,
                        "error": (
                            f"Azure DevOps API returned "
                            f"{response.status_code}: {response.text}"
                        ),
                    }
                ),
                status_code=response.status_code,
                mimetype="application/json",
            )

        data = response.json()

        repositories = []

        for repo in data.get("value", []):
            repositories.append(
                {
                    "id": repo.get("id"),
                    "name": repo.get("name"),
                    "project": repo.get("project", {}).get("name"),
                    "default_branch": repo.get("defaultBranch"),
                    "web_url": repo.get("webUrl"),
                    "remote_url": repo.get("remoteUrl"),
                    "size": repo.get("size"),
                    "is_disabled": repo.get("isDisabled", False),
                }
            )

        result = {
            "connected": True,
            "organization": "Gitlas-poc",
            "project": "Gitlas",
            "repository_count": len(repositories),
            "repositories": repositories,
        }

        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as exc:
        return func.HttpResponse(
            json.dumps(
                {
                    "connected": False,
                    "error": str(exc),
                }
            ),
            status_code=500,
            mimetype="application/json",
        )

