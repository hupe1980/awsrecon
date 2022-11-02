package output

import (
	"os"

	"github.com/aquasecurity/table"
)

type Table struct {
	header []string
	body   [][]string
}

func NewTable(header []string) *Table {
	return &Table{
		header: header,
	}
}

func (o *Table) Add(row []string) {
	o.body = append(o.body, row)
}

func (o *Table) Print() {
	t := table.New(os.Stdout)
	t.SetHeaders(o.header...)
	t.AddRows(o.body...)
	t.SetHeaderStyle(table.StyleBold)
	t.SetRowLines(true)
	t.SetLineStyle(table.StyleCyan)
	t.SetDividers(table.UnicodeRoundedDividers)
	t.Render()
}
