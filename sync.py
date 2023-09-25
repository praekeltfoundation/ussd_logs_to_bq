import base64
import hashlib
import json
import os
import re
from datetime import datetime, timedelta
from urllib.parse import urljoin

import requests
from google.api_core.exceptions import BadRequest
from google.cloud import bigquery
from google.cloud.exceptions import NotFound
from google.oauth2 import service_account
from sentry_sdk import init

if "SENTRY_DSN" in os.environ:
    init(os.environ["SENTRY_DSN"])

BQ_KEY_PATH = os.environ.get("BQ_KEY_PATH", "bigquery/bq_credentials.json")
BQ_DATASET = os.environ.get("BQ_DATASET", "tbconnect_test")
BQ_TABLE = os.environ.get("BQ_TABLE", "ussd_states")
INITIAL_BACKFILL_DAYS = int(os.environ.get("INITIAL_BACKFILL_DAYS", "5"))
CHUNK_SIZE_MINUTES = int(os.environ.get("CHUNK_SIZE_MINUTES", "30"))
LOKI_URL = os.environ.get("LOKI_URL", "http://loki.monitoring.svc.cluster.local:3100")

credentials = service_account.Credentials.from_service_account_file(
    BQ_KEY_PATH,
    scopes=["https://www.googleapis.com/auth/cloud-platform"],
)

bigquery_client = bigquery.Client(
    credentials=credentials,
    project=credentials.project_id,
)


def hash_string(text):
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode(
        "utf-8"
    )


def get_logs_chunk(query, start, end, limit=5000):
    params = params = {
        "query": query,
        "start": start.timestamp(),
        "end": end.timestamp(),
        "direction": "BACKWARD",
        "limit": limit,
    }
    resp = requests.get(
        urljoin(LOKI_URL, "/loki/api/v1/query_range"), stream=True, params=params
    )
    if resp.status_code == 200:
        return logs_from_response(resp)
    resp.raise_for_status()
    return []


def get_logs(query, start, end):
    delta = timedelta(minutes=CHUNK_SIZE_MINUTES)
    chunk_start = start
    chunk_end = chunk_start + delta
    if chunk_end > end:
        chunk_end = end

    while chunk_end != end:
        print(f"Fetching {delta} logs between", chunk_start, chunk_end)
        yield get_logs_chunk(query, chunk_start, chunk_end)
        chunk_start = chunk_end
        chunk_end = chunk_end + delta
        if chunk_end > end:
            chunk_end = end
    return []


def logs_from_response(resp):
    logs = []
    for result in resp.json()["data"]["result"]:
        for ts, stream in result["values"]:
            log_line = stream
            # Some json logs are being parsed automatically.
            if type(stream) is dict:
                log_line = stream["log"]
            logs.append(
                (datetime.fromtimestamp(int(ts) / 1e9), parse_ussd_log_line(log_line))
            )
    print("Logs: ", len(logs))
    return logs


def parse_ussd_log_line(line):
    match = re.findall(r"Loaded user: (.*)", line)
    if match:
        data = json.loads(match[0].encode("utf-8").decode("unicode_escape"))
        addr = data["addr"].lstrip("+")
        addr = f"+{addr}"
        data["addr"] = hash_string(addr)
        return data


def get_table_id(table_name):
    return f"{credentials.project_id}.{BQ_DATASET}.{table_name}"


def get_last_record(table, field):
    try:
        bigquery_client.get_table(get_table_id(table))
        print(f"Table {table} exists.")
    except NotFound:
        print(f"Table {table} is not found.")
        return None, None, None

    query = (
        f"SELECT EXTRACT(DATETIME from {field}), msisdn, state FROM "
        f"{BQ_DATASET}.{table} ORDER BY {field} DESC limit 1;"
    )

    for row in bigquery_client.query(query).result():
        if row[0]:
            return row[0], row[1], row[2]
    return None, None, None


def upload_to_bigquery(table, data, fields):
    schema = [
        bigquery.SchemaField(field, data_type) for field, data_type in fields.items()
    ]

    job_config = bigquery.LoadJobConfig(
        source_format="NEWLINE_DELIMITED_JSON",
        write_disposition="WRITE_APPEND",
        schema=schema,
    )

    job = bigquery_client.load_table_from_json(
        data, f"{BQ_DATASET}.{table}", job_config=job_config
    )
    try:
        job.result()
    except BadRequest as e:
        for e in job.errors:
            print("ERROR: {}".format(e["message"]))


if __name__ == "__main__":
    query = (
        '{app="ussd-tb-check",container="ussd-tb-check"}!~ "27820001001"'
        '|~"Loaded user:"'
    )
    print("Fetching last record date...")
    last_end, last_msisdn, last_state = get_last_record(BQ_TABLE, "timestamp")
    print("Latest record timestamp in BQ: ", last_end)
    start = last_end or datetime.now() - timedelta(days=INITIAL_BACKFILL_DAYS)
    end = datetime.now()

    bq_log_fields = {
        "timestamp": "TIMESTAMP",
        "msisdn": "STRING",
        "state": "STRING",
        "answers": "STRING",
    }

    for logs in get_logs(query, start, end):
        data = []
        for ts, log in logs:
            if not log:
                continue
            if "name" not in log["state"]:
                continue
            # skip the existing record
            if (
                ts == last_end
                and log["addr"] == last_msisdn
                and log["state"] == last_state
            ):
                continue

            data.append(
                {
                    "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    "msisdn": log["addr"],
                    "state": log["state"]["name"],
                    "answers": json.dumps(log["answers"]),
                }
            )

        print(f"Syncing {len(data)} Records...")
        upload_to_bigquery(BQ_TABLE, data, bq_log_fields)
