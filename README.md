# nmap-did-what

**nmap-did-what** is a Grafana docker container and a Python script to parse Nmap XML output to an SQLite database. The SQLite database is used as a datasource within Grafana to view the Nmap scan details in a dashboard.

Full Tutorial is available here - [Nmap Dashboard using Grafana](https://hackertarget.com/nmap-dashboard-with-grafana/)

![Grafana Dashboard](https://hackertarget.com/images/nmap-grafana-dashboard.webp)

## Overview

The project consists of two main components:

1. A Python script that parses Nmap XML output and stores the data in an SQLite database.
2. A Grafana Docker container with a pre-configured dashboard for visualizing the Nmap scan data.

### File Structure

- **/src/nmap-to-sqlite.py**: A Python script that parses Nmap XML output and stores the data in an SQLite database.
- **docker-compose.yml**: A Docker Compose file that sets up the Grafana container, configuring it to use the SQLite database and including volumes for persistent storage and configuration.
- **dashboard.yml**: A configuration file that specifies the dashboard provider settings for Grafana.
- **datasource.yml**: Configures Grafana to use the SQLite database containing the Nmap scan data as the data source.
- **/data/nmap_results.db**: location in container for the SQLite DB.
- **run_nmap**: an opinionated bash executable to rerun an nmap command with consistent outputs


## Usage

### Prerequisites:

1. **Nmap**
  - to install on Linux systems such as Fedora 40, it is as simple as `sudo dnf install nmap`
  - the installation can be verified with `namp --version`
2. **Docker and Docker Compose**
  - an exhaustive installation guide for Linux can be found [here](https://docs.docker.com/engine/install/fedora/)


### Deployment:

1. **Clone the repository and cd into project**

```
git clone https://github.com/hackertarget/nmap-did-what.git
cd nmap-did-what
```

2. **Run Nmap**
- Make the bash file `run_nmap` executable by running `chmod +x run_nmap`.
  - _Recommended_: access should be set with `chmod 750 <file name>`.
- This script will prompt you to choose a non-default path for writing the output of this command.
  - Note: this non-default path will need to passed as a param to the next step (see notes).

3. **Parse Nmap XML output**

Run the `nmap-to-sqlite.py` script to parse your Nmap XML output and store the data in an SQLite database:

```
python src/nmap-to-sqlite.py
```
Notes:
- **--xml_file**: if no path to nmap output XML file is given, the default used is `data/nmap_output.xml`
  - _if_ a non-default path was used, this must be specified as a parameter
- **--db_path**: if not path to db is given, the default used is `data/nmap_results.db`

4. **Start the Grafana Container**

Use Docker Compose to start the Grafana container:

```
cd nmap-did-what
docker-compose up -d
```

5. **Access Grafana**

Once the container is up and running, access the Grafana dashboard through your web browser:

```
http://localhost:3000
```

Use the default Grafana credentials (admin/admin) unless changed in the configuration. The Nmap dashboard should be loaded with the data from your Nmap scans.
- *Note*: if you change and then forget the admin password, you can reset it with the grafana cli within the container:
```
docker exec -it <continer-id> grafana-cli admin reset-admin-password <your-new-password>
```

Multiple scans can be reviewed within the DB and the Nmap Dashboard time filters can be used to the view the scan information based on the time stamps from the scans.

## Systemd Automation
**For Use on Linux Systems**
> For a more exhuastive overview of systemd, visit [this site](https://systemd.io/)

### Nmap Scanning Service
1. Move the service file to `/etc/systemd/system/nmap-scan.service` (recommended: `sudo cp <target file> <destination>`)
2. Move the timer file to `/etc/systemd/system/nmap-scan.timer`
3. Replace /path/to/your/run_nmap in the service file with the actual path to the bash script in the project's parent directory called `run_nmap`
4. Adjust the subnet in the service file (192.168.1.0/24) if necessary.

### Nmap Parsing Service
The systemd directory also contains service and timer files for automatically parsing nmap XML output:

1. Move the parsing service file: `sudo cp systemd/nmap-parse.service /etc/systemd/system/`
2. Move the parsing timer file: `sudo cp systemd/nmap-parse.timer /etc/systemd/system/`
3. Update the path in `/etc/systemd/system/nmap-parse.service` - replace `/path/to/projects/nmap-did-what` with your actual project path
4. The timer is configured to run daily at 00:15 (15 minutes after midnight), which allows time for the nmap scan to complete first

**After creating these files, you need to enable and start both timers:**
```
sudo systemctl daemon-reload
sudo systemctl enable nmap-scan.timer
sudo systemctl enable nmap-parse.timer
sudo systemctl start nmap-scan.timer
sudo systemctl start nmap-parse.timer
```

This setup will run your nmap scan script daily with the --auto flag, then parse the results 15 minutes later, ensuring the XML output is processed into the SQLite database automatically.
A few notes:

- The service runs as root. This is often necessary for nmap scans, but ensure this aligns with your security requirements.
- The OnCalendar=daily setting in the timer file runs the scan once per day. You can adjust this if you need a different schedule.
- The Persistent=true setting ensures that if the system is off when the timer is supposed to run, it will run when the system next boots up.

#### Troubleshooting Systemd
- If the nmap bash script has 750 privileges (veryify with `stat <file name>`), but the logs from [journalctl](https://man7.org/linux/man-pages/man1/journalctl.1.html) read permission denied, check if SELinux is enabled with `sestatus`.
- If the output looks like:
```
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   permissive
Mode from config file:          enforcing
Policy MLS status:              enabled
Policy deny_unknown status:     allowed
Memory protection checking:     actual (secure)
Max kernel policy version:      33
```
- Then you can set SELinux to permissive with `sudo setenforce 0` and try running the service again.
- If the script proves to successfully run via Systemd, you can reenable SELinux if you'd like with `sudo setenforce 1`.
- If SELinux is to continue to be enabled on the system, then you will need to define the context for what actions are allowed on files, particularly ones in your home directory.
  - This is accomplished with a simple command `sudo chcon -t bin_t /path/to/nmap-did-what/run_nmap`
  - However, this is not persistent across reboots. For this, run:
    - `sudo semanage fcontext -a -t bin_t "/path/to/nmap-did-what/run_nmap"` ~> adding the file to context rules.
    - `sudo restorecon -v /path/to/nmap-did-what/run_nmap` ~> applies these rules to the file.
  - Confirm the context with `ls -Z /path/to/nmap-did-what/run_nmap`


## Next Steps: Customization

- Modify the `nmap-to-sqlite.py` script to extract additional information from the Nmap XML output or to change the structure of the SQLite database.
- Custom Dashboard are easy to implement, simply adjust the Grafana dashboard to your requirements. Export the JSON of the Dashboard and replace the default Dashboard or create additional dashboard. The ability to spin up a Grafana Docker container with a prebuilt Dashboard is a nice feature.
- Automation is possible, as you can simply run **nmap** with a cron job, parse the XML with **nmap-to-sqlite.py** and the updated DB will have the newly acquired scan information.

## Credits

Thanks to the Nmap and Grafana projects for providing powerful open-source tools for network scanning and data visualization.
