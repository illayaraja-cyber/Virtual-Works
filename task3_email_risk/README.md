# Task 3: Email Risk Analyzer

```bash
python3 email_risk_analyzer.py --text 'URGENT: send your password at http://bit.ly/demo'
python3 email_risk_analyzer.py --file message.txt
```

Uses local heuristics to flag urgency, sensitive-data requests, and suspicious links. It never follows links.
