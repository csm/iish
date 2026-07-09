# Harness self-check, not a real installer: exercises the same
# native-execution + subprocess + env-file-append machinery a real
# installer would, entirely offline, and actually runs to completion
# under iish today. Its job is to prove scripts/verify-installers.sh's
# "iish finished; now verify the program it installed" path works at
# all — otherwise that path would stay completely unexercised until a
# real corpus script gets far enough to reach it (see PLAN.md
# milestone 7).
mkdir -p /home/tester/bin
cp /bin/true /home/tester/bin/toytool
chmod +x /home/tester/bin/toytool
echo 'export PATH="/home/tester/bin:$PATH"' >> ~/.profile
