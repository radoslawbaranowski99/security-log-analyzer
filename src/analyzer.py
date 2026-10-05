# Import os to work with directories and file paths
import os

# Import the regular expressions module used to search for patterns in log lines
import re

# Import argparse to handle command-line arguments
import argparse
# Import Counter to count how many times each host appears
from collections import Counter

# Importing Date and Time
from datetime import datetime

# Path to the log file that will be analyzed
LOG_FILE = "logs/linux_2k.log"

# Minimum number of failed attempts required to generate an alert
THRESHOLD = 5

# Generate a timestamp for the report filename
REPORT_TIMESTAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Human-readable timestamp displayed inside the report
REPORT_DATE = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Path for the generated security report
REPORT_FILE = f"reports/security_report_{REPORT_TIMESTAMP}.txt"

# Analyze the specified log file
def analyze_log(log_file):
    print(f"[INFO] Analyzing log file: {log_file}")

    # Store detected security events
    failed_hosts = []
    root_attempts = []
    unknown_user_events = []
    successful_users = []
    su_users = []
    ftp_sources = []
    ftp_problem_events = []
    logrotate_errors = []
    service_events = []

    # Open the log file in read mode
    with open(log_file, "r", encoding="utf-8", errors="ignore") as file:

        # Read the log file line by line
        for line in file:

        # Detect opened su sessions
            if "su(pam_unix)" in line and "session opened for user" in line:
                # Extract the target username from the su session entry
                su_user_match = re.search(r"session opened for user ([^\s]+)", line)
           
                # Store the username if it was successfully extracted
                if su_user_match:
                    su_users.append(su_user_match.group(1))

            # Detect FTP events
            if "ftpd" in line:

                # Detect FTP connection events
                if "connection from" in line:

                    # Extract the source IP address
                    ftp_match = re.search(r"connection from ([^\s]+)", line)

                    # Store the source IP if it was successfully extracted
                    if ftp_match:
                        ftp_sources.append(ftp_match.group(1))

                # Detect FTP events involving unknown users or timeouts
                if "User unknown" in line or "timed out" in line:
                    ftp_problem_events.append(line.strip())

            # Detect abnormal logrotate events
            if "logrotate" in line and "exited abnormally" in line:
                logrotate_errors.append(line.strip())

            # Detect system service lifecycle events
            if (
                "restart" in line.lower()
                or "startup succeeded" in line.lower()
                or "shutdown succeeded" in line.lower()
            ):
                service_events.append(line.strip())

            # Skip the current line if it is not related to the SSH service
            if "sshd" not in line:
                continue

        # Detect SSH events involving an unknown user
            if "user unknown" in line:
                unknown_user_events.append(line.strip())

        # Detect successful SSH sessions
            if "session opened for user" in line:
                user_match = re.search(r"session opened for user ([^\s]+)", line)
                if user_match:
                    successful_users.append(user_match.group(1))

            # Process only SSH authentication failure events
            if "authentication failure" in line:

                # Search for the value after "rhost="
                host_match = re.search(r"rhost=([^\s]+)", line)

                # Search for the value after "user="
                user_match = re.search(r"user=([^\s]+)", line)

                # Continue only if a source host was found in the log entry
                if host_match:

                    # Extract the captured host from the regex result
                    host = host_match.group(1)

                    # Add the source host to the list of failed authentication attempts
                    failed_hosts.append(host)

                    # Check whether the log contains a username and whether it is "root"
                    if user_match and user_match.group(1) == "root":

                        # Add the source host to the root login attempts list
                        root_attempts.append(host)
    return (
        failed_hosts,
        root_attempts,
        unknown_user_events,
        successful_users,
        su_users,
        ftp_sources,
        ftp_problem_events,
        logrotate_errors,
        service_events,
    )

def print_results(
        failed_counts,
        root_counts,
        unknown_user_events,
        successful_counts,
        su_counts,
        ftp_counts,
        ftp_problem_events,
        logrotate_errors,
        service_events,
):
    print()
    print("=== SSH Security Analyzer ===")
    print()
    print("[1] Failed authentication sources:")
    
    for host, count in failed_counts.most_common():
        if count >= THRESHOLD:
            print(f"[ALERT] {host}: {count} failed authentication attempts")
        else:
            print(f"[INFO] {host}: {count} failed authentication attempts")
    print()
    print("[2] Root login attempts:")
    for host, count in root_counts.most_common():
        print(f"[ALERT] {host} -> {count} attempts against root")
    
    print()
    print("[3] Unknown user events:")

    if unknown_user_events:
        print(f"[ALERT] Detected {len(unknown_user_events)} SSH events involving unknown users")
    else:
        print("[INFO] No unknown user events detected")
    print()
    print("[4] Successful SSH sessions:")

    if successful_counts:
        for user, count in successful_counts.most_common():
            print(f"[INFO] {user} -> {count} successful sessions")
    else:
        print("[INFO] No successful SSH sessions detected")

    print()
    print("[5] SU sessions:")

    if su_counts:

        for user, count in su_counts.most_common():
            print(f"[INFO] {user} -> {count} opened su sessions")

    else:
        print("[INFO] No opened su sessions detected")


    print()
    print("[6] FTP activity:")

    if ftp_counts:
        for source, count in ftp_counts.most_common():
            status = "ALERT" if count >= THRESHOLD else "INFO"
            print(f"[{status}] {source} -> {count} FTP connections")

    else:
        print("[INFO] No FTP connections detected")

    if ftp_problem_events:
        print(f"[ALERT] Detected {len(ftp_problem_events)} FTP unknown-user/timeout events")
    else:
        print("[INFO] No FTP unknown-user/timeout events detected")

    print()
    print("[7] System events:")

    if logrotate_errors:
        print(f"[ALERT] Detected {len(logrotate_errors)} abnormal logrotate events")
    else:
        print("[INFO] No abnormal logrotate events detected")

    if service_events:
        print(f"[INFO] Detected {len(service_events)} service lifecycle events")
    else:
        print("[INFO] No service lifecycle events detected")

    print()
    print("=== Summary ===")

    print(f"Total failed SSH attempts: {sum(failed_counts.values())}")
    print(f"Unique failed-auth sources: {len(failed_counts)}")
    print(f"Root-targeting sources: {len(root_counts)}")
    print(f"Unknown user events: {len(unknown_user_events)}")
    print(f"Successful SSH sessions: {sum(successful_counts.values())}")
    print(f"Users with successful SSH sessions: {len(successful_counts)}")
    print(f"Opened SU sessions: {sum(su_counts.values())}")
    print(f"Users with opened SU sessions: {len(su_counts)}")
    print(f"FTP connections: {sum(ftp_counts.values())}")
    print(f"Unique FTP sources: {len(ftp_counts)}")
    print(f"FTP unknown-user/timeout events: {len(ftp_problem_events)}")
    print(f"Abnormal logrotate events: {len(logrotate_errors)}")
    print(f"Service lifecycle events: {len(service_events)}")

# Save analysis summary to a report file
def save_report(
    report_file,
    report_date,
    log_file,
    failed_counts,
    root_counts,
    unknown_user_events,
    successful_counts,
    su_counts,
    ftp_counts,
    ftp_problem_events,
    logrotate_errors,
    service_events,
):
    #Create the report directory if it does not exist
    os.makedirs(os.path.dirname(report_file), exist_ok=True)        

    with open(report_file, "w", encoding="utf-8") as report:
        report.write("=== Security Log Analysis Report ===\n\n")
        report.write(f"Analyzed log file: {log_file}\n")
        report.write(f"Report generated: {report_date}\n\n")

        report.write("=== Summary ===\n")
        report.write(f"Total failed SSH attempts: {sum(failed_counts.values())}\n")
        report.write(f"Unique failed-auth sources: {len(failed_counts)}\n")
        report.write(f"Root-targeting sources: {len(root_counts)}\n")
        report.write(f"Unknown user events: {len(unknown_user_events)}\n")
        report.write(f"Successful SSH sessions: {sum(successful_counts.values())}\n")
        report.write(f"Users with successful SSH sessions: {len(successful_counts)}\n")
        report.write(f"Opened SU sessions: {sum(su_counts.values())}\n")
        report.write(f"Users with opened SU sessions: {len(su_counts)}\n")
        report.write(f"FTP connections: {sum(ftp_counts.values())}\n")
        report.write(f"Unique FTP sources: {len(ftp_counts)}\n")
        report.write(f"FTP unknown-user/timeout events: {len(ftp_problem_events)}\n")
        report.write(f"Abnormal logrotate events: {len(logrotate_errors)}\n")
        report.write(f"Service lifecycle events: {len(service_events)}\n")

    print()
    print(f"[INFO] Report saved to: {report_file}")

# Parse command-line arguments
def parse_arguments():
    
    # Create the command-line argument parser
    parser = argparse.ArgumentParser(
        description="Analyze Linux security logs."
    )

    # Add an optional log file path argument
    parser.add_argument(
        "log_file",
        nargs="?",
        default=LOG_FILE,
        help=f"Path to the log file (default: {LOG_FILE})",
    )

    # Parse and return the provided arguments
    return parser.parse_args()


def main():
    args = parse_arguments()

    try:

        (
            failed_hosts,
            root_attempts,
            unknown_user_events,
            successful_users,
            su_users,
            ftp_sources,
            ftp_problem_events,
            logrotate_errors,
            service_events,
        ) = analyze_log(args.log_file)

    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {args.log_file}")
        return
    except PermissionError:
        print(f"[ERROR] Log file not found: {args.log_file}")
        return

    # Count detected events
    failed_counts = Counter(failed_hosts)
    root_counts = Counter(root_attempts)
    successful_counts = Counter(successful_users)
    su_counts = Counter(su_users)
    ftp_counts = Counter(ftp_sources)

    print_results(
        failed_counts,
        root_counts,
        unknown_user_events,
        successful_counts,
        su_counts,
        ftp_counts,
        ftp_problem_events,
        logrotate_errors,
        service_events,
    )

    save_report(
        REPORT_FILE,
        REPORT_DATE,
        args.log_file,
        failed_counts,
        root_counts,
        unknown_user_events,
        successful_counts,
        su_counts,
        ftp_counts,
        ftp_problem_events,
        logrotate_errors,
        service_events,
    )
if __name__ == "__main__":
    main()