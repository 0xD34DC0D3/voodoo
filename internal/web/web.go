// Package web holds the shared HTML chrome — layout template, stylesheet,
// fonts — that the auth server renders its pages with.
package web

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed layout.html
var layoutFS embed.FS

//go:embed static
var staticFS embed.FS

// Static holds the stylesheet and fonts, rooted so that "style.css" is a
// top-level entry (ready to mount under a "/static" route prefix).
var Static = func() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return sub
}()

// Templates parses the shared layout plus every *.html page in pages into one
// template set, so feature packages only embed their own page templates.
func Templates(pages fs.FS) *template.Template {
	t := template.Must(template.ParseFS(layoutFS, "layout.html"))
	return template.Must(t.ParseFS(pages, "*.html"))
}

// Chrome is the shared layout data every HTML page embeds: the tab title and,
// when the request is authenticated, who is logged in (shown in the header).
type Chrome struct {
	Title     string
	UserEmail string
	IsAdmin   bool
	// Nav is the active top-level section ("home", "keys", "admin") used to
	// mark the current nav link; Wide widens the content column for
	// table-heavy pages; Flash is a one-shot success notice surfaced after a
	// redirect (post/redirect/get).
	Nav   string
	Wide  bool
	Flash string
}
