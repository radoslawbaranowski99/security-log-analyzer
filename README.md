# Security Log Analyzer

Security Log Analyzer is a Python-based tool for analyzing Linux system logs and detecting security-related events.

The analyzer processes log files line by line and identifies selected patterns related to authentication, user sessions, network services, and system events.

## Features

The analyzer currently detects:

- Failed SSH authentication attempts
- Authentication attempts against the root account
- SSH events involving unknown users
- Successful SSH sessions
- SU session activity
- FTP connections and selected FTP problems
- Abnormal logrotate events
- Service lifecycle events such as startup, shutdown, and restart

The analyzer also:

- Counts detected events using Python `Counter`
- Uses a configurable threshold to highlight repeated activity
- Generates a summary of detected events
- Creates timestamped text reports
- Accepts a log file path from the command line
- Handles missing files and permission errors
- Automatically creates the report directory when necessary

## Project Structure

```text
security-log-analyzer/
├── logs/
│   └── linux_2k.log
├── reports/
│   └── security_report_YYYY-MM-DD_HH-MM-SS.txt
├── src/
│   └── analyzer.py
├── tests/
│   └── test_analyzer.py
└── README.md
```

## Installation

The project requires Python 3.

Create a virtual environment:

```bash
python3 -m venv .venv
```

Activate the virtual environment:

```bash
source .venv/bin/activate
```

Install the testing dependency:

```bash
python -m pip install pytest
```

## Usage

Run the analyzer using the default log file:

```bash
.venv/bin/python src/analyzer.py
```

Analyze a specific log file:

```bash
.venv/bin/python src/analyzer.py logs/linux_2k.log
```

Display command-line help:

```bash
.venv/bin/python src/analyzer.py --help
```

If no log file path is provided, the analyzer uses `logs/linux_2k.log` by default.

After the analysis, a timestamped report is automatically saved in the `reports/` directory.

## Testing

Automated tests are implemented using `pytest`.

Run all tests with:

```bash
.venv/bin/python -m pytest tests/test_analyzer.py -v
```

The test suite verifies the detection of:

- Failed SSH authentication attempts
- Authentication attempts against root
- Unknown SSH users
- Successful SSH sessions
- SU sessions
- FTP connections
- Abnormal logrotate events
- Service lifecycle events

The project currently includes 8 automated tests.

## INFO and ALERT

The analyzer uses two status levels:

- `INFO` - indicates that an event was detected and recorded for analysis.
- `ALERT` - indicates that repeated activity reached the configured threshold and may require further investigation.

An `ALERT` does not automatically mean that an attack occurred. The analyzer detects patterns and events that may require additional security analysis.

The default alert threshold is set to 5 events.

## Limitations

The analyzer is a rule-based educational security tool and does not independently confirm whether detected activity is malicious.

The results should be treated as indicators for further investigation.

The analyzer currently focuses on selected Linux log patterns, including SSH, SU, FTP, logrotate, and service lifecycle events. Log formats from other systems or services may require additional parsing rules.