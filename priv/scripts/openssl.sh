#!/bin/sh
set -u
set -e

case $1 in
   secret)
      test -e $2/secret.pem || openssl genrsa -out $2/secret.pem 2048
      cat $2/secret.pem
      ;;

   public)
      test -e $2/public.pem || openssl rsa -in $2/secret.pem -pubout > $2/public.pem
      cat $2/public.pem
      ;;
esac
