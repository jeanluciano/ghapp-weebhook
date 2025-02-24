import time
import uuid
import jwt
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()

GITHUB_APP_NAME = "..."
GITHUB_APP_ID = "..."
GITHUB_PRIVATE_KEY = "..."
GH_CLIENT_ID = "..."
GH_CLIENT_SECRET = "..."
JWT_SECRET = "..."
JWT_ALGORITHM = "HS256"


INSTALLATIONS_DB = {}

# Fake Account
ACCOUNT_ID = uuid.uuid4()


def generate_state_token(account_id: str) -> str:
    """
    Creates a short-lived JWT that encodes which user/account is installing.
    """
    payload = {
        "account_id": account_id,
        "exp": int(time.time()) + 300,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def decode_state_token(token: str) -> str:
    """
    Decodes the JWT to retrieve the account_id.
    Raises HTTP 400 if invalid or expired.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["account_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="State token has expired.")
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail="Invalid state token.")


@app.get("/", response_class=HTMLResponse)
async def index_page():
    account_id = str(ACCOUNT_ID)

    # See if this account has an installation
    installation_id = INSTALLATIONS_DB.get(account_id)

    if not installation_id:
        # If there's NO installation yet, show the "Install" flow
        state_token = generate_state_token(account_id)
        install_url = f"https://github.com/apps//installations/new?state={state_token}"

        html = f"""
        <html>
        <head><title>Fake UI</title></head>
        <body>
            <h1>Install Prefect Cloud GitHub App</h1>
            <p>Account ID in Prefect Cloud: {account_id}</p>
            <a href="{install_url}">
                <button>Install GitHub App</button>
            </a>
        </body>
        </html>
        """
    else:
        # If we DO have an installation, fetch and show available repositories
        app_jwt = generate_app_jwt()
        repos = await list_installation_repos(app_jwt, installation_id)

        repo_options = "\n".join(
            f'<option value="{repo["full_name"]}">{repo["full_name"]}</option>'
            for repo in repos
        )

        html = f"""
        <html>
        <head>
            <title>GitHub Repo Viewer</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                select, button {{
                    padding: 8px;
                    font-size: 16px;
                    border-radius: 6px;
                }}
                select {{
                    width: 100%;
                    max-width: 400px;
                }}
                button {{
                    background-color: #2ea44f;
                    color: white;
                    border: 1px solid rgba(27,31,35,0.15);
                    cursor: pointer;
                }}
                button:hover {{
                    background-color: #2c974b;
                }}
            </style>
        </head>
        <body>
            <h1>Your GitHub Repositories</h1>
            <p>Your account_id: {account_id}</p>
            <p>Associated installation_id: {installation_id}</p>
            <hr>
            <h2>Select a Repository to View Files</h2>
            <form action="/github/list-files" method="get">
                <input type="hidden" name="installation_id" value="{installation_id}">
                <select id="repo-select" required onchange="updateForm(this.value)">
                    <option value="">Select a repository...</option>
                    {repo_options}
                </select>
                <input type="hidden" name="owner" id="owner-input">
                <input type="hidden" name="repo" id="repo-input">
                <br><br>
                <button type="submit" id="submit-button" disabled>View Repository Files</button>
            </form>

            <script>
            function updateForm(fullName) {{
                const submitButton = document.getElementById('submit-button');
                const ownerInput = document.getElementById('owner-input');
                const repoInput = document.getElementById('repo-input');

                if (fullName) {{
                    const [owner, repo] = fullName.split('/');
                    ownerInput.value = owner;
                    repoInput.value = repo;
                    submitButton.disabled = false;
                }} else {{
                    submitButton.disabled = true;
                    ownerInput.value = '';
                    repoInput.value = '';
                }}
            }}
            </script>
        </body>
        </html>
        """
    return HTMLResponse(html)


@app.get("/github/callback")
async def github_callback(request: Request):
    """
    The callback after the user installs the GitHub App (and does user-level OAuth).
    Query params often include:
      - code: the OAuth code for user-level access
      - installation_id: the ID of the installed app
      - setup_action: "install" or "update"
      - state: the JWT we sent
    """
    code = request.query_params.get("code")
    installation_id = request.query_params.get("installation_id")
    state_token = request.query_params.get("state")

    if not code:
        raise HTTPException(status_code=400, detail="Missing OAuth code.")
    if not installation_id:
        raise HTTPException(status_code=400, detail="Missing installation_id.")
    if not state_token:
        raise HTTPException(status_code=400, detail="Missing state token.")

    # Decode the state to get our internal account_id
    account_id = decode_state_token(state_token)

    # 1) Exchange the "code" for a user access token (user-level).
    user_token = await exchange_code_for_user_token(code, state_token)
    if not user_token:
        raise HTTPException(
            status_code=400, detail="Failed to exchange code for user token."
        )

    # 2) Verify the user truly has access to (or "owns") this installation_id.
    #    We'll do that by calling GET /user/installations with the user's token
    #    and seeing if the returned list of installations includes `installation_id`.
    if not await user_owns_installation(user_token, installation_id):
        raise HTTPException(
            status_code=403, detail="Installation is not associated with this user."
        )

    # 3) Store in DB: This ties our local account to the GitHub installation ID.
    INSTALLATIONS_DB[account_id] = installation_id

    # 4) Redirect to a success page
    return RedirectResponse(url="/setup")


@app.get("/setup", response_class=HTMLResponse)
def setup_page():
    html = """
    <html>
    <head><title>Setup Complete</title></head>
    <body>
        <h1>GitHub App & OAuth Flow Complete!</h1>
        <p>Your installation is verified and your user token was successfully retrieved.</p>
        <p><a href="/installations">View In-Memory Installations</a></p>
    </body>
    </html>
    """
    return HTMLResponse(html)


@app.get("/installations", response_class=HTMLResponse)
def list_installations():
    """
    Debug page to list account_id -> installation_id pairs
    """
    list_items = "".join(
        f"<li>Account: {acct}, Installation: {inst}</li>"
        for acct, inst in INSTALLATIONS_DB.items()
    )
    html = f"""
    <html>
    <head><title>Installations</title></head>
    <body>
        <h1>In-Memory Installation Mappings</h1>
        <ul>{list_items}</ul>
        <p><a href="/">Back to index</a></p>
    </body>
    </html>
    """
    return HTMLResponse(html)


async def exchange_code_for_user_token(code: str, state: str) -> str:
    """
    Exchange the GitHub OAuth 'code' for a user access token.
    This is the standard GitHub OAuth flow:
      POST https://github.com/login/oauth/access_token
      with client_id, client_secret, code, and state.

    Returns the access token string, or None if failed.
    """
    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": GH_CLIENT_ID,
        "client_secret": GH_CLIENT_SECRET,
        "code": code,
        "state": state,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(token_url, headers=headers, data=data)
        resp_data = resp.json()
        access_token = resp_data.get("access_token")

        # If there's an error or no token, return None
        if not access_token:
            return None
        return access_token


async def user_owns_installation(user_token: str, installation_id: str) -> bool:
    url = "https://api.github.com/user/installations"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"token {user_token}",
    }

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return False

        data = resp.json()
        # data is like: {"installations": [ { "id": 12345, ...}, ... ]}
        installations = data.get("installations", [])
        for inst in installations:
            if str(inst["id"]) == str(installation_id):
                return True

        return False


async def list_installation_repos(app_jwt: str, installation_id: int) -> list[dict]:
    # First get an installation token
    installation_token = await get_installation_token(app_jwt, installation_id)
    if not installation_token:
        raise HTTPException(
            status_code=400, detail="Failed to obtain installation token."
        )

    # Use the token to list accessible repositories
    repos_url = "https://api.github.com/installation/repositories"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {installation_token}",
    }

    async with httpx.AsyncClient() as client:
        resp = await client.get(repos_url, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"Error fetching repositories: {resp.text}",
            )
        data = resp.json()
        return data["repositories"]


def generate_app_jwt() -> str:
    now = int(time.time())
    exp = now + (10 * 60)  # 10 minutes from now

    payload = {
        "iat": now,
        "exp": exp,
        "iss": GITHUB_APP_ID,  # your GitHub App ID
    }

    encoded_jwt = jwt.encode(payload, GITHUB_PRIVATE_KEY, algorithm="RS256")
    return encoded_jwt


async def get_installation_token(app_jwt: str, installation_id: int) -> str:
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {app_jwt}",
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, headers=headers)
        if resp.status_code == 201:
            return resp.json().get("token")
        else:
            print("Error getting installation token:", resp.text)
            return None


@app.get("/github/list-files", response_class=HTMLResponse)
async def list_files_in_repo(owner: str, repo: str, installation_id: int):
    # 1) Generate a JWT to authenticate as your GitHub App.
    app_jwt = generate_app_jwt()

    # 2) Exchange the app JWT for an installation token
    installation_token = await get_installation_token(app_jwt, installation_id)
    if not installation_token:
        raise HTTPException(
            status_code=400, detail="Failed to obtain installation token."
        )

    # 3) Use the installation token to call the GitHub Contents API
    contents_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {installation_token}",
    }

    async with httpx.AsyncClient() as client:
        resp = await client.get(contents_url, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"Error fetching repo contents: {resp.text}",
            )
        contents = resp.json()

    files_html = ""
    for item in sorted(contents, key=lambda x: (x["type"] != "dir", x["name"].lower())):
        icon = "📁" if item["type"] == "dir" else "📄"
        size = f"({item['size']} bytes)" if item["type"] == "file" else ""
        files_html += f"""
        <div class="file-item">
            <span>{icon} <a href="{item["html_url"]}" target="_blank">{item["name"]}</a> {size}</span>
        </div>
        """

    html = f"""
    <html>
    <head>
        <title>{owner}/{repo} Contents</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                max-width: 1000px;
                margin: 0 auto;
                padding: 20px;
            }}
            .repo-header {{
                border-bottom: 1px solid #e1e4e8;
                padding-bottom: 20px;
                margin-bottom: 20px;
            }}
            .file-item {{
                padding: 8px;
                border-bottom: 1px solid #eaecef;
            }}
            .file-item:hover {{
                background-color: #f6f8fa;
            }}
            a {{
                color: #0366d6;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
            .back-button {{
                display: inline-block;
                margin-top: 20px;
                padding: 6px 12px;
                background-color: #fafbfc;
                border: 1px solid rgba(27,31,35,0.15);
                border-radius: 6px;
                color: #24292e;
                text-decoration: none;
            }}
            .back-button:hover {{
                background-color: #f3f4f6;
            }}
        </style>
    </head>
    <body>
        <div class="repo-header">
            <h1>📂 {owner}/{repo}</h1>
            <p>Repository contents at root level</p>
        </div>

        <div class="files-container">
            {files_html}
        </div>

        <a href="/" class="back-button">← Back to repository list</a>
    </body>
    </html>
    """

    return HTMLResponse(html)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="localhost", port=3000)