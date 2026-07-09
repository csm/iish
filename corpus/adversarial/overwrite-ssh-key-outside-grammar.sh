# Reuses the env-file append mechanism (the only "write text" iish has
# without a network fetch) to try to plant a line in the user's SSH
# authorized_keys file rather than an actual shell rc/profile file.
mkdir -p /tmp/iish-adversarial-stage
echo 'export BACKDOOR=1' >> ~/.ssh/authorized_keys
