# Import the analyzer function from the src directory
from src.analyzer import analyze_log

# Test detection of a failed SSH authentication attempt
def test_failed_ssh_authentixation(tmp_path):
    log_file = tmp_path / "test.log"

    log_file.write_text(
        "Jun 15 10:00:00 server sshd[1234]: "
        "authentication failure; rhost=192.168.1.100 user=test\n"
    )

    results = analyze_log(log_file)

    failed_hosts = results[0]

    assert failed_hosts == ["192.168.1.100"]

# Test detection of a failed SSH authentication attempt against root
def test_root_ssh_authentication(tmp_path):
    log_file = tmp_path / "test_root.log"

    log_file.write_text(
        "Jun 15 10:00:00 server sshd[1234]: "
        "authentication failure; rhost=10.0.0.50 user=root\n"
    )

    results = analyze_log(log_file)

    root_attempts = results[1]

    assert root_attempts ==["10.0.0.50"]

# Test detection of an unknown SSH user event
def test_unknown_ssh_user(tmp_path):
    log_file = tmp_path / "test_unknown_user.log"

    log_file.write_text(
        "Jun 15 10:00:00 server sshd[1234]: user unknown\n"
    )

    results = analyze_log(log_file)

    unknown_user_events = results[2]

    assert len(unknown_user_events) == 1

# Test detection of a successful SSH session
def test_successful_ssh_session(tmp_path):
    log_file = tmp_path / "test_successful_ssh.log"

    log_file.write_text(
        "Jun 15 10:00:00 server sshd[1234]: "
        "session opened for user test \n"
    )

    results = analyze_log(log_file)

    successful_users = results[3]

    assert successful_users == ["test"]

# Test detection of an opened SU session
def test_su_session(tmp_path):
    log_file = tmp_path / "test_su.log"

    log_file.write_text(
        "Jun 15 10:00:00 server su(pam_unix): "
        "session opened for user cyrus\n"
    )

    results = analyze_log(log_file)

    su_users = results[4]

    assert su_users == ["cyrus"]

# Test detection of an FTP connection
def test_ftp_connection(tmp_path):
    log_file = tmp_path / "test_ftp.log"

    log_file.write_text(
        "Jun 17 07:07:00 server ftpd[29504]: "
        "connection from 192.168.1.50 at Fri Jun 17 07:07:00 2005\n"
    )

    results = analyze_log(log_file)

    ftp_sources = results[5]

    assert ftp_sources == ["192.168.1.50"]

# Test detection of an abnormal logrotate event
def test_logrotate_error(tmp_path):
    log_file = tmp_path / "test_logrotate.log"

    log_file.write_text(
        "Jun 15 04:06:20 server logrotate: "
        "ALERT exited abnormally with [1]\n"
    )

    results = analyze_log(log_file)

    logrotate_errors = results[7]

    assert len(logrotate_errors) == 1

# Test detection of a service lifecycle event
def test_service_event(tmp_path):
    log_file = tmp_path / "test_service.log"

    log_file.write_text(
        "Jun 19 04:09:11 server syslogd 1.4.1: restart.\n"
    )

    results = analyze_log(log_file)
    service_events = results[8]

    assert len(service_events) == 1