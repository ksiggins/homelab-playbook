# homelab-playbook

## Requirements
Install the ansible galaxy collections and roles that the playbooks use beforehand
```
ansible-galaxy install --force -r requirements.yml
```

## Ansible Vault
To create a new encrypted data file, run the following command:

```
ansible-vault create foo.yml
```

First you will be prompted for a password. After providing a password, the tool will launch whatever editor you have defined with $EDITOR, and defaults to vi. Once you are done with the editor session, the file will be saved as encrypted data.

The default cipher is AES (which is shared-secret based).

To edit an encrypted file in place, use the ansible-vault edit command. This command will decrypt the file to a temporary file and allow you to edit the file, saving it back when done and removing the temporary file:

```
ansible-vault edit foo.yml
```

Should you wish to change your password on a vault-encrypted file or files, you can do so with the rekey command:

```
ansible-vault rekey foo.yml bar.yml baz.yml
```

This command can rekey multiple data files at once and will ask for the original password and also the new password.

If you have existing files that you wish to encrypt, use the ansible-vault encrypt command. This command can operate on multiple files at once:

```
ansible-vault encrypt foo.yml bar.yml baz.yml
```

If you have existing files that you no longer want to keep encrypted, you can permanently decrypt them by running the ansible-vault decrypt command. This command will save them unencrypted to the disk, so be sure you do not want ansible-vault edit instead:

```
ansible-vault decrypt foo.yml bar.yml baz.yml
```

If you want to view the contents of an encrypted file without editing it, you can use the ansible-vault view command:

```
ansible-vault view foo.yml bar.yml baz.yml
```

Result:

```
the_secret: !vault |
      $ANSIBLE_VAULT;1.1;AES256
      62313365396662343061393464336163383764373764613633653634306231386433626436623361
      6134333665353966363534333632666535333761666131620a663537646436643839616531643561
      63396265333966386166373632626539326166353965363262633030333630313338646335303630
      3438626666666137650a353638643435666633633964366338633066623234616432373231333331
      6564
```
