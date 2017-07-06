#!/bin/sh
set -u
set -e

aws s3 cp $1 - 
