# Creates a staging directory (legitimately owned by this run), then
# plants a symlink inside it pointing at a directory the run does NOT
# own, then deletes "into" the owned directory but really through the
# symlink -- the exact bug iish's ledger ownership check must not fall
# for (see exec.rs::assert_no_symlink_escape).
mkdir -p /tmp/iish-adversarial-stage/pkg
ln -s /home/tester/victim /tmp/iish-adversarial-stage/pkg/escape
rm -rf /tmp/iish-adversarial-stage/pkg/escape/marker.txt
