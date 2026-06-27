import re
from pathlib import Path

# Fix test_cli.py
cli_path = Path("tests/test_cli.py")
cli_content = cli_path.read_text()
cli_content = cli_content.replace('mock_sleep.assert_called_once_with(1.5)', 'mock_sleep.assert_called_once_with(0.3)')
cli_path.write_text(cli_content)

# Fix test_firewall.py
fw_path = Path("tests/test_firewall.py")
fw_content = fw_path.read_text()

old_list = """[
            "insert",
            "rule",
            "inet",
            "ttp",
            "filter_out",
            "counter",
            "reject",
        ]"""
new_list = """[
            "insert",
            "rule",
            "inet",
            "ttp",
            "filter_out",
            "meta",
            "l4proto",
            "udp",
            "counter",
            "reject",
        ]"""
fw_content = fw_content.replace(old_list, new_list)
fw_path.write_text(fw_content)

print("Tests updated.")
