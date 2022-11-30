from sync import parse_ussd_log_line


def test_parse_log_line_with_state():
    log_str = open("ussd.log", "r").read()
    parsed = parse_ussd_log_line(log_str)
    assert parsed["addr"] == "89+2gNIOoXKJLqDc3PvicYvigvb/o4Kn7rA8KaZXch8="
    assert parsed["state"]["name"] == "state_age"
