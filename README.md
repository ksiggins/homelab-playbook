# Ansible Playbook Framework

This repository provides a flexible structure for Ansible playbooks designed to provision and manage various server configurations. The framework supports modular roles and tasks that can be easily extended to manage different applications or configurations. The initial implementation includes a setup for Podman, demonstrating the framework's capabilities.

## Directory Structure

The repository is organized to support clarity and extensibility:

- **playbooks/**: Contains specific Ansible playbooks for orchestrating roles to set up and manage applications or services. Each subdirectory corresponds to a domain or application, e.g., `podman/`.

- **roles/**: Includes modular roles encapsulating tasks and handlers. Roles can be shared across different playbooks, promoting reusability. Each role typically includes:
  - `tasks/`: Main tasks to execute.
  - `handlers/`: Handlers triggered by tasks when changes occur.
  - `defaults/`: Default variables for the role.

- **inventory/**: Stores host inventories divided by environment, such as:
  - `production/`: Production environment configuration.
  - `staging/`: Staging environment configuration.

- **scripts/**: Contains utility scripts for running playbooks efficiently. The `run.sh` script automates the execution of playbooks with appropriate inventories and additional options.

- **ansible.cfg**: Configuration file for Ansible settings that apply globally to all playbook runs.
## Extensibility

The current setup is designed with future extensibility in mind:

- **Adding New Playbooks**: You can add new directories within `playbooks/` to create playbooks for other services or applications.
- **Creating New Roles**: Within `roles/`, you can add new roles that define tasks and configurations for unique services or systems.

## Podman Implementation

The initial implementation includes playbooks and roles for managing Podman:

- **Playbooks for Podman**:
  - `playbooks/podman/install.yml`: Installs and configures Podman on target hosts.
  - `playbooks/podman/uninstall.yml`: Removes Podman from target hosts.
  - `playbooks/podman/verify.yml`: Checks the installation and configuration of Podman.

- **Roles for Podman**: Logical grouping of tasks and configurations to manage Podman installation and verification.

### Running Podman Playbooks with Scripts

The `scripts/run.sh` script streamlines the execution of Podman-related playbooks and supports additional Ansible arguments for further customization:

1. **Install Podman**
   ```bash
   scripts/run.sh podman install <inventory>
   ```

2. **Verify Installation with Verbose Output**
   ```bash
   scripts/run.sh podman verify <inventory> -vvv
   ```
   - The `-vvv` flag increases the verbosity level of Ansible's output, providing detailed execution logs which can help in debugging and understanding the tasks performed.

3. **Uninstall Podman for a Specific Host**
   ```bash
   scripts/run.sh podman uninstall <inventory> --limit <host>
   ```
   - The `--limit <host>` option confines the playbook execution to a specific host within the inventory, allowing for targeted operations.

Replace `<inventory>` with `staging` or `production`, and `<host>` with the specific host identifier.

Including `ansible-args` enables more flexible and powerful management of your infrastructure by allowing command customization directly through the script.

## Requirements

- **Ansible**: Ensure Ansible is installed on the control node, as it orchestrates the configuration management processes across your servers.

- **SSH Key-Based Authentication**: It is recommended to use SSH keys for server authentication. This method enhances security by eliminating the need for password-based logins and enabling seamless, automated connections between Ansible and your managed nodes.

- **Privilege Escalation**: The playbooks might require elevated permissions to execute specific tasks. The scripts are configured to prompt for the sudo password where necessary using the `--ask-become-pass` Ansible flag. This approach is preferred over configuring "passwordless sudo" (using the `NOPASSWD` directive in the sudoers file), as it offers a balance between security and convenience by ensuring that privilege escalation remains deliberate and user-approved.

## Contribution

Contributions are welcome. Feel free to add new features, improve existing ones, or report issues.
