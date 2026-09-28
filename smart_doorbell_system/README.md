# Smart Doorbell and Gate Access Control

A synchronous edge-cloud access control system simulating a smart doorbell, an edge gateway, and a cloud verification service. It demonstrates secure, encrypted communication across device boundaries.

## Architecture Overview

```text
[ Doorbell Device ] ---> [ Edge Gateway ] ---> [ Cloud Service ] ---> [ SQLite Database ]
      (Client)             (Port: 5000)          (Port: 8000)
```

### Security Features

The system employs **hop-by-hop AES-256-GCM encryption** for all inter-process communications, ensuring confidentiality, integrity, and authenticity.

- **Device to Edge:** Secured via the `DOORBELL_EDGE_KEY` (32-byte hex) environment variable.
- **Edge to Cloud:** Secured via the `DOORBELL_CLOUD_KEY` (32-byte hex) environment variable.

*Note: By default, the services will use hardcoded fallback keys if the environment variables are not set. In a production environment, ensure these variables are properly configured.*

### File Layout

```text
smart_doorbell_system/
|-- cloud_service.py     # Cloud verification service
|-- crypto.py            # AES-256-GCM encryption primitives
|-- doorbell_device.py   # Client-side device simulator
|-- edge_gateway.py      # Intermediate validation and routing
|-- requirements.txt     # Python dependencies
|-- access_control.db    # Created when the cloud service starts
|-- edge_requests.log    # Created after the gateway receives a request
```

## Security Architecture

The system uses hop-by-hop AES-256-GCM encryption for all communication.
- **Device to Edge:** Secured via `DOORBELL_EDGE_KEY` (32-byte hex).
- **Edge to Cloud:** Secured via `DOORBELL_CLOUD_KEY` (32-byte hex).

By default, the services will use hardcoded fallback keys if the environment variables are not set.

## Running Locally

1. **Set up a virtual environment** (optional but recommended):
   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

2. **Install dependencies**:
   ```powershell
   python -m pip install -r requirements.txt
   ```

3. **Start the services** (in separate terminals):
   ```powershell
   # Terminal 1
   python cloud_service.py

   # Terminal 2
   python edge_gateway.py

   # Terminal 3
   python doorbell_device.py
   ```

### Usage

Once the `doorbell_device.py` is running, you can enter a visitor's name. By default, the cloud service accepts `Alice`, `Bob`, or `Charlie`. Type `exit` to stop the device simulator.

To view aggregate access statistics, run:
```powershell
curl http://localhost:8000/api/analytics/summary
```

## Continuous Integration

GitHub Actions automatically runs on every push and pull request. The `CI` workflow includes:
- **Unit tests**: Validating functionality across all modules.
- **Code quality**: Linting and style checks with `ruff`.
- **Security scanning**: Static analysis with `bandit` and dependency auditing with `pip-audit`.

### Production Considerations

While this project demonstrates robust hop-by-hop encryption and basic access architecture, it is a prototype. Before deploying to a production environment:
- **Secret Management**: Provide securely generated 32-byte hex keys via `DOORBELL_EDGE_KEY` and `DOORBELL_CLOUD_KEY` environment variables instead of relying on the local fallbacks.
- **Database**: Replace the local SQLite file with a hardened, remote relational database.
- **Routing**: Update the hardcoded local service URLs (`localhost`) with proper service discovery or static IPs.
- **Data Privacy**: The edge gateway logs have been sanitized to only store encrypted payload hashes. However, the cloud verification service still stores plaintext access logs in its database. Avoid using real personal data.