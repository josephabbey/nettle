package services

import (
	"embed"
	"io/fs"
)

//go:embed webui/*
var webAssets embed.FS

var webAssetFS = mustSubFS("webui")
var webIndexHTML = mustReadWebAsset("index.html")

func mustSubFS(dir string) fs.FS {
	sub, err := fs.Sub(webAssets, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

func mustReadWebAsset(name string) []byte {
	data, err := webAssets.ReadFile("webui/" + name)
	if err != nil {
		panic(err)
	}
	return data
}
