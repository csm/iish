# Same trick as symlink-escape-rm.sh, but for chmod: real chmod(2)
# follows a symlink to its target, so "chmod a path under something we
# own" must not silently reach outside it.
mkdir -p /tmp/iish-adversarial-stage/pkg2
ln -s /home/tester/victim2 /tmp/iish-adversarial-stage/pkg2/escape
chmod 777 /tmp/iish-adversarial-stage/pkg2/escape/marker2.txt
