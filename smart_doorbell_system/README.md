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