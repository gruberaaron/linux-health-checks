# Linux Health Checks

A collection of scripts and tools for performing health checks on Linux systems. This project helps system administrators and DevOps engineers monitor and maintain the health of their Linux servers by automating common checks and reporting issues.

## Features

- Automated health checks for CPU, memory, disk, and network
- Customizable checks and thresholds
- Easy-to-read output and logs
- Modular and extensible design

## Usage

1. Clone this repository:
   ```sh
   git clone https://github.com/gruberaaron/linux-health-checks.git
   cd linux-health-checks
   ```

2. Run the appropriate script for your operating system:
   ```sh
   python3 rocky_health_check.py
   ```

3. Review the output and logs for any detected issues.

## Requirements

- Bash (or compatible shell)
- Standard Linux utilities (e.g., `top`, `df`, `free`, `netstat`)
- Sudo privileges may be required for some checks
- Python 3

## Customization

You can add or modify health check scripts in the repository to suit your environment. Refer to the comments in each script for guidance.

## Contributing

Contributions are welcome! Please open issues or submit pull requests for improvements or new checks.

## License

This project is open source. See the LICENSE file for details.
