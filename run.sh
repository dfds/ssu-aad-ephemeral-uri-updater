#!/bin/sh

init()
{
  go install github.com/GeertJohan/go.rice/rice@latest
  cd model/static && rice embed-go
  cd ../..
}

init

go run cmds/main.go