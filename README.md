# homelab-playbook

## Requirements
Install the ansible galaxy collections and roles that the playbooks use beforehand

The installation directory is defined in the ansible.cfg file to be roles/galaxy
Remove roles/galaxy to reinstall with updated versions or clear out unused versions
```bash
rm -rf .ansible
ansible-galaxy install -r requirements.yml
```

## Python
To update python dependencies, use pip-compile:
```bash
pip-compile requirements.in --no-header --no-annotate --strip-extras --output-file requirements.txt
```

## Ansible Facts
Ansible facts are data related to your remote systems, including operating systems, IP addresses, attached filesystems, and more. You can access this data in the ansible_facts variable.

To see the ‘raw’ information as gathered, run this command at the command line:
```bash
ansible <hostname> -m ansible.builtin.setup
```

## Pre-Commit

This project uses [`pre-commit`](https://pre-commit.com) hooks to catch common issues like YAML formatting, whitespace, Ansible linting, and more **before they reach Git**.

### Installation (macOS/Homebrew)

```bash
brew install pre-commit
pre-commit install
```

This installs the tool and sets up the Git hook so checks run automatically on each commit.

### Test it Manually

To manually run all hooks on all files at any time:
```bash
pre-commit run --all-files
```
This is great to catch everything before pushing or for CI checks.

Run on staged changes (like Git does on commit):
```bash
pre-commit run
```
Runs only on files you've staged with git add.

### Required Files

The following config files are required and included in the repo:
- .pre-commit-config.yaml – defines the hooks to run (YAML, Ansible, etc.)
- .ansible-lint – defines Ansible linting rules and profile
- .yamllint – optional, if custom YAML linting rules are needed

These will automatically be used by the pre-commit framework once installed.

### Updating Hooks

To update the hook versions to their latest compatible releases:
```bash
pre-commit autoupdate
```

## Ansible Vault
To create a new encrypted data file, run the following command:

```bash
ansible-vault create foo.yml
```

First you will be prompted for a password. After providing a password, the tool will launch whatever editor you have defined with $EDITOR, and defaults to vi. Once you are done with the editor session, the file will be saved as encrypted data.

The default cipher is AES (which is shared-secret based).

To edit an encrypted file in place, use the ansible-vault edit command. This command will decrypt the file to a temporary file and allow you to edit the file, saving it back when done and removing the temporary file:

```bash
ansible-vault edit foo.yml
```

Should you wish to change your password on a vault-encrypted file or files, you can do so with the rekey command:

```bash
ansible-vault rekey foo.yml bar.yml baz.yml
```

This command can rekey multiple data files at once and will ask for the original password and also the new password.

If you have existing files that you wish to encrypt, use the ansible-vault encrypt command. This command can operate on multiple files at once:

```bash
ansible-vault encrypt foo.yml bar.yml baz.yml
```

If you have existing files that you no longer want to keep encrypted, you can permanently decrypt them by running the ansible-vault decrypt command. This command will save them unencrypted to the disk, so be sure you do not want ansible-vault edit instead:

```bash
ansible-vault decrypt foo.yml bar.yml baz.yml
```

If you want to view the contents of an encrypted file without editing it, you can use the ansible-vault view command:

```bash
ansible-vault view foo.yml bar.yml baz.yml
```

Result:

```bash
the_secret: !vault |
      $ANSIBLE_VAULT;1.1;AES256
      62313365396662343061393464336163383764373764613633653634306231386433626436623361
      6134333665353966363534333632666535333761666131620a663537646436643839616531643561
      63396265333966386166373632626539326166353965363262633030333630313338646335303630
      3438626666666137650a353638643435666633633964366338633066623234616432373231333331
      6564
```
