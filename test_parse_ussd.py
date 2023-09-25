import json
from sync import parse_ussd_log_line, logs_from_response


class MockResponse:
    def __init__(self, text):
        self.text = text

    def json(self):
        return json.loads(self.text)


def test_parse_log_line_with_state():
    log_str = open("ussd.log", "r").read()
    parsed = parse_ussd_log_line(log_str)
    assert parsed["addr"] == "89+2gNIOoXKJLqDc3PvicYvigvb/o4Kn7rA8KaZXch8="
    assert parsed["state"]["name"] == "state_age"


def test_parse_logs_from_response():
    response = MockResponse(open("loki_response.json", "r").read())
    logs = logs_from_response(response)
    assert len(logs) == 4
