package views

import (
	"embed"
	"io"

	"github.com/0xD34DC0D3/voodoo/internal/web"
)

//go:embed *.html
var pagesFS embed.FS

var templates = web.Templates(pagesFS)

func Render(w io.Writer, name string, data any) error {
	return templates.ExecuteTemplate(w, name, data)
}
