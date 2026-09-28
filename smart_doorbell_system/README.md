# Smart Doorbell and Gate Access Control

Minimal synchronous edge-cloud baseline with three local processes:

```text
doorbell_device.py -> edge_gateway.py -> cloud_service.py -> SQLite
       : client              :5000                 :8000
```

## Layout

```text
smart_doorbell_system/
|-- cloud_service.py
|-- doorbell_device.py
|-- edge_gateway.py
|-- requirements.txt
|-- README.md
|-- access_control.db       # created when the cloud service starts
|-- edge_requests.log       # created after the gateway receives a request
```

## Run locally

From this directory, create and activate a virtual environment if desired, then install dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start each service in a separate terminal, in this order:

```powershell
python cloud_service.py
python edge_gateway.py
python doorbell_device.py
```

The device accepts `Alice`, `Bob`, or `Charlie` by default. Type `exit` to stop it. View aggregate statistics with:

```powershell
curl http://localhost:8000/api/analytics/summary
```

## Continuous integration

GitHub Actions runs on every push and pull request. The `CI` workflow runs the
unit tests, checks Python code with Ruff and Bandit, and audits installed
dependencies with `pip-audit`. To make successful checks mandatory before a
pull request can merge, open the repository's **Settings > Rules > Rulesets**
and require the `Tests and security checks` status check.

These checks are a starting point, not a production security certification.
They do not provide real visitor identity verification, encrypt visitor names,
move visitor records into a protected production database, remove the
hardcoded local service URLs, or provide production-grade availability and
audit controls. Those require application and deployment changes beyond CI.
Visitor names are currently stored in SQLite and included in the gateway's
local request log, so do not use real personal data with this prototype.