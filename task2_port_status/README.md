# Task 2: Port Status Checker

Check one TCP port on an authorized host:

```bash
python3 port_status_checker.py 22
python3 port_status_checker.py 443 example.com --timeout 3
```

The tool checks one port only; it does not scan ranges.
