package output

import (
	"encoding/csv"
	"os"
	"strings"

	"github.com/aquasecurity/table"
)

type Output struct {
	header []string
	body   [][]string
}

func New(header []string) *Output {
	return &Output{
		header: header,
	}
}

func (o *Output) Add(row []string) {
	o.body = append(o.body, row)
}

func (o *Output) PrintTable() {
	t := table.New(os.Stdout)
	t.SetHeaders(o.header...)
	t.AddRows(o.body...)
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(true)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.Render()
}

func (o *Output) SaveAsCSV(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	header := make([]string, len(o.header))
	for _, h := range o.header {
		header = append(header, strings.ReplaceAll(h, "\n", ""))
	}

	csvWriter := csv.NewWriter(f)
	if err := csvWriter.Write(header); err != nil {
		return err
	}

	for _, b := range o.body {
		row := make([]string, len(b))

		for _, r := range b {
			r = strings.ReplaceAll(r, ",\n", ", ")
			r = strings.ReplaceAll(r, "\n", "")

			row = append(row, r)
		}

		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	csvWriter.Flush()

	return nil
}
