package gofpdi

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/happyreturns/gofpdf"
	"github.com/happyreturns/gofpdf/internal/example"
)

func ExampleNewImporter() error {
	// create new pdf
	pdf := gofpdf.New("P", "pt", "A4", "")

	// for testing purposes, get an arbitrary template pdf as stream
	rs, _ := getTemplatePdf()

	// create a new Importer instance
	imp := NewImporter()

	// import first page and determine page sizes
	tpl, err := imp.ImportPageFromStream(pdf, &rs, 1, "/MediaBox")
	if err != nil {
		return err
	}

	pageSizes := imp.GetPageSizes()
	nrPages := len(imp.GetPageSizes())

	// add all pages from template pdf
	for i := 1; i <= nrPages; i++ {
		pdf.AddPage()
		if i > 1 {
			tpl, err = imp.ImportPageFromStream(pdf, &rs, i, "/MediaBox")
			if err != nil {
				return err
			}
		}
		imp.UseImportedTemplate(pdf, tpl, 0, 0, pageSizes[i]["/MediaBox"]["w"], pageSizes[i]["/MediaBox"]["h"])
	}

	// output
	fileStr := example.Filename("contrib_gofpdi_Importer")
	err = pdf.OutputFileAndClose(fileStr)
	example.Summary(err, fileStr)
	// Output:
	// Successfully generated ../../pdf/contrib_gofpdi_Importer.pdf
	return nil
}

func TestGofpdiConcurrent(t *testing.T) {
	wg := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pdf := gofpdf.New("P", "mm", "A4", "")
			pdf.AddPage()
			rs, _ := getTemplatePdf()
			imp := NewImporter()
			tpl, err := imp.ImportPageFromStream(pdf, &rs, 1, "/MediaBox")
			if err != nil {
				t.Fail()
			}
			imp.UseImportedTemplate(pdf, tpl, 0, 0, 210.0, 297.0)
			// write to bytes buffer
			buf := bytes.Buffer{}
			if err := pdf.Output(&buf); err != nil {
				t.Fail()
			}
		}()
	}
	wg.Wait()
}

func getTemplatePdf() (io.ReadSeeker, error) {
	tpdf := gofpdf.New("P", "pt", "A4", "")
	tpdf.AddPage()
	tpdf.SetFont("Arial", "", 12)
	tpdf.Text(20, 20, "Example Page 1")
	tpdf.AddPage()
	tpdf.Text(20, 20, "Example Page 2")
	tbuf := bytes.Buffer{}
	err := tpdf.Output(&tbuf)
	return bytes.NewReader(tbuf.Bytes()), err
}
