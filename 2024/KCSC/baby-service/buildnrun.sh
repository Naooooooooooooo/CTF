#!/bin/sh

 docker build . -t go_chall
 docker run --rm -d -p8888:8888 -it go_chall
