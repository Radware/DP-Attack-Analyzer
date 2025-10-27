import re
from common import *
import paramiko

def _open_sftp(hostname: str, username: str, password: str, port: int = 22, timeout: int = 15):
    """
    Open an SFTP session via Paramiko and return (ssh, sftp).
    Caller must close both: sftp.close(); ssh.close()
    Host key checking is disabled to mirror the original pysftp.CnOpts(hostkeys=None).
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=hostname,
        port=int(port),
        username=username,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=timeout,
    )
    sftp = ssh.open_sftp()
    return ssh, sftp

def get_attack_log(v, device_ips, from_month, start_year, to_month=None):
    """
    Pull BDOS attack logs via SFTP from DefensePro devices.

    Args:
        v: object exposing v.getDeviceData(ip) -> dict with
           ['deviceSetup']['deviceAccess'] keys: httpsUsername, httpsPassword, cliPort
        device_ips: iterable of device IP strings
        from_month: e.g., '01' .. '12'
        start_year: e.g., '2024' (string or int)
        to_month: optional '01' .. '12'. If provided, use a simple regex range like the original code.

    Returns:
        list of local file paths downloaded.
    """
    remote_path = '/disk/var/attacklog/bdos'

    start_year = str(start_year)
    if to_month:
        pattern = re.compile(rf"^BDOS{start_year}[{from_month}-{to_month}]")
    else:
        pattern = re.compile(rf"^BDOS{start_year}{from_month}")

    all_found_files = []

    for device_ip in device_ips:
        device_ip = device_ip.strip()
        try:
            update_log(f"Connecting to {device_ip} ... ",newline=False)
            dpData = v.getDeviceData(device_ip)
            access = dpData['deviceSetup']['deviceAccess']
            username = access['httpsUsername']
            password = access['httpsPassword']
            port = access.get('cliPort', 22)

            update_log(f"Connecting to {device_ip}:{port} ... ", newline=False)
            ssh, sftp = _open_sftp(device_ip, username, password, port)
            update_log("connected.")

            try:
                files = sftp.listdir(remote_path)
            except FileNotFoundError:
                update_log(f"Remote path not found on {device_ip}: {remote_path}")
                sftp.close(); ssh.close()
                continue

            # Filter files by pattern
            found_files = [f for f in files if pattern.match(f)]
            if found_files:
                update_log(f"Found files on {device_ip}: {found_files}")
                for fname in found_files:
                    remote_file_path = f"{remote_path}/{fname}"
                    local_file_path = f"{temp_folder}{fname}_{dpData['name']}.txt"
                    all_found_files.append(local_file_path)

                    # Download
                    try:
                        sftp.get(remote_file_path, local_file_path)
                        update_log(f"Downloaded {remote_file_path} -> {local_file_path}")
                    except Exception as de:
                        update_log(f"Download failed for {remote_file_path} on {device_ip}: {de}")
            else:
                update_log(f"No files found on {device_ip} matching BDOS{start_year}{from_month}" + (f"-{to_month}" if to_month else ""))

            # Cleanup per-host
            sftp.close()
            ssh.close()

        except Exception as e:
            update_log(f"Failed on {device_ip}: {e}")

    update_log("SFTP operations completed.")
    return all_found_files
