package iam

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func (d *Definitions) parseActionsTable(filename, prefix string, table *goquery.Selection) error {
	rows := table.Find("tr")
	rowNumber := 0

	for rowNumber < rows.Length() {
		row := rows.Eq(rowNumber)

		cells := row.Find("td")
		if cells.Length() == 0 {
			// Skip header row, which has th and not td cells
			rowNumber = rowNumber + 1
			continue
		}

		rowspanStr := cells.Eq(0).AttrOr("rowspan", "1")

		rowspan, err := strconv.Atoi(rowspanStr)
		if err != nil {
			return fmt.Errorf("cannot convert rowspan %s in filename %s", rowspanStr, filename)
		}

		var (
			actionName string
			apiDocLink string
		)

		cells.Eq(0).Find("a").Each(func(i int, s *goquery.Selection) {
			if href, ok := s.Attr("href"); ok {
				apiDocLink = href
			}
			actionName = strings.Trim(s.Text(), " \n")
		})

		if actionName == "" {
			actionName = strings.Trim(cells.Eq(0).Text(), " \n")
		}

		description := strings.Trim(cells.Eq(1).Text(), " \n")
		accessLevel := strings.Trim(cells.Eq(2).Text(), " \n")

		resourceCell := 3
		resourceTypes := make(map[string]*ActionResourceType)

		// TODO
		for rowspan > 0 {
			if cells.Length() == 3 || cells.Length() == 6 {
				resourceType := strings.Trim(cells.Eq(resourceCell).Text(), " \n")

				conditionKeysElement := cells.Eq(resourceCell + 1)
				conditionKeys := []string{}

				if conditionKeysElement.Text() != "" {
					conditionKeysElement.Find("a").Each(func(i int, s *goquery.Selection) {
						conditionKeys = append(conditionKeys, s.Text())
					})
				}

				dependentActionsElement := cells.Eq(resourceCell + 2)
				dependentActions := []string{}

				if dependentActionsElement.Text() != "" {
					dependentActionsElement.Find("p").Each(func(i int, s *goquery.Selection) {
						dependentActions = append(dependentActions, strings.Trim(s.Text(), " \n"))
					})
				}

				required := false
				if strings.Contains(resourceType, "*") {
					required = true
					resourceType = strings.Trim(resourceType, "*")
				}

				resourceTypes[resourceType] = &ActionResourceType{
					Name:             resourceType,
					Required:         required,
					ConditionKeys:    conditionKeys,
					DependentActions: dependentActions,
				}
			}

			rowspan = rowspan - 1

			if rowspan > 0 {
				rowNumber = rowNumber + 1
				resourceCell = 0
				row = rows.Eq(rowNumber)
				cells = row.Find("td")
			}
		}

		if strings.Contains(actionName, "[permission only]") {
			actionName = strings.Split(actionName, " ")[0]
		}

		if s, ok := d.definitions[prefix]; ok {
			if s.Actions == nil {
				s.Actions = make(map[string]*ActionDefinition)
			}

			s.Actions[actionName] = &ActionDefinition{
				Name:          actionName,
				Description:   description,
				AccessLevel:   accessLevel,
				ResourceTypes: resourceTypes,
				APIDocLink:    apiDocLink,
			}
		}

		rowNumber = rowNumber + 1
	}

	return nil
}

func (d *Definitions) parseResourceTypesTable(filename, prefix string, table *goquery.Selection) error {
	rows := table.Find("tr")

	for i := range rows.Nodes {
		row := rows.Eq(i)

		cells := row.Find("td")
		if cells.Length() == 0 {
			// Skip header row, which has th, not td cells
			continue
		}

		if cells.Length() != 3 {
			return fmt.Errorf("unexpected number of resource cells %d in %s", cells.Length(), filename)
		}

		resource := strings.Trim(cells.Eq(0).Text(), " \n")
		arn := strings.Trim(cells.Eq(1).Text(), " \n")

		conditions := []string{}

		cells.Eq(2).Find("p").Each(func(i int, s *goquery.Selection) {
			conditions = append(conditions, strings.Trim(s.Text(), " \n"))
		})

		if s, ok := d.definitions[prefix]; ok {
			if s.ResourceTypes == nil {
				s.ResourceTypes = make(map[string]*ResourceType)
			}

			s.ResourceTypes[resource] = &ResourceType{
				Name:       resource,
				ARN:        arn,
				Conditions: conditions,
			}
		}
	}

	return nil
}

func (d *Definitions) parseConditionKeysTable(filename, prefix string, table *goquery.Selection) error {
	rows := table.Find("tr")

	for i := range rows.Nodes {
		row := rows.Eq(i)

		cells := row.Find("td")
		if cells.Length() == 0 {
			// Skip header row, which has th, not td cells
			continue
		}

		if cells.Length() != 3 {
			return fmt.Errorf("unexpected number of condition cells %d in %s", cells.Length(), filename)
		}

		name := strings.Trim(cells.Eq(0).Text(), " \n")
		description := strings.Trim(cells.Eq(1).Text(), " \n")
		valueType := strings.Trim(cells.Eq(2).Text(), " \n")

		if s, ok := d.definitions[prefix]; ok {
			if s.ConditionKeys == nil {
				s.ConditionKeys = make(map[string]*ConditionKey)
			}

			s.ConditionKeys[name] = &ConditionKey{
				Name:        name,
				Description: description,
				Type:        valueType,
			}
		}
	}

	return nil
}
