run:
	docker build -t foo . && docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --rm -v "`pwd`:/rust" -it foo "cd /rust; cargo run"
