docker build -t crawlee-python .

docker run --rm -v $(pwd):/app crawlee-python