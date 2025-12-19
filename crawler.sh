docker build -t crawlee-python .

docker run --rm -v $(pwd)/data:/app/data crawlee-python