package output

import (
	"os"

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
