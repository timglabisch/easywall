run:
	docker build -t foo . && docker run -v "`pwd`:/rust" -it foo "cd /rust; cargo run"
