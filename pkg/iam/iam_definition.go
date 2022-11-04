package iam

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/hupe1980/awsrecon/pkg/common"
)

const (
	BaseURL = "https://docs.aws.amazon.com/service-authorization/latest/reference"
)

//go:embed resource
var embedFS embed.FS

type ActionResourceType struct {
	Name             string
	Required         bool
	ConditionKeys    []string
	DependentActions []string
}

type ActionDefinition struct {
	Name          string
	Description   string
	AccessLevel   string
	ResourceTypes map[string]*ActionResourceType
	APIDocLink    string
}

type ResourceType struct {
	Name       string
	ARN        string
	Conditions []string
}

type ConditionKey struct {
	Name        string
	Description string
	Type        string
}

type ServiceDefinition struct {
	Name             string
	Prefix           string
	AuthorizationURL string
	Actions          map[string]*ActionDefinition
	ResourceTypes    map[string]*ResourceType
	ConditionKeys    map[string]*ConditionKey
}

type Definitions struct {
	definitions map[string]*ServiceDefinition
}

func NewDefinitions() (*Definitions, error) {
	return NewDefinitionsFromFS("resource/iam-definition.json", embedFS, false)
}

func NewDefinitionsFromFS(filename string, fs fs.ReadFileFS, gzipFile bool) (*Definitions, error) {
	data, err := fs.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if gzipFile {
		b := bytes.NewBuffer(data)

		r, err := gzip.NewReader(b)
		if err != nil {
			return nil, err
		}

		var resB bytes.Buffer
		if _, err = resB.ReadFrom(r); err != nil {
			return nil, err
		}

		data = resB.Bytes()
	}

	var definitions map[string]*ServiceDefinition
	if err := json.Unmarshal(data, &definitions); err != nil {
		return nil, err
	}

	return &Definitions{
		definitions: definitions,
	}, nil
}

func NewDefinitionFromReference() (*Definitions, error) {
	d := &Definitions{
		definitions: make(map[string]*ServiceDefinition),
	}

	res, err := http.Get(fmt.Sprintf("%s/reference_policies_actions-resources-contextkeys.html", BaseURL))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		return nil, err
	}

	filenames := []string{}

	doc.Find("div.highlights a").Each(func(i int, s *goquery.Selection) {
		// For each item found, get the name.
		name, _ := s.Attr("href")
		if name[:2] == "./" {
			name = name[2:]
		}

		if strings.HasPrefix(name, "list_") {
			filenames = append(filenames, fmt.Sprintf("%s/%s", BaseURL, name))
		}
	})

	//TODO
	//filenames = []string{"https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html", "https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazondynamodb.html", "https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsamplify.html"}

	for _, filename := range filenames {
		// nolint gosec no user input
		res, err := http.Get(filename)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		doc, err := goquery.NewDocumentFromReader(res.Body)
		if err != nil {
			return nil, err
		}

		mainContent := doc.Find("#main-content")

		if mainContent == nil {
			continue
		}

		title := mainContent.Find("h1.topictitle").Text()
		re := regexp.MustCompile(`Actions, resources, and condition keys for *`)
		title = strings.Trim(re.ReplaceAllString(title, ""), " ")

		var servicePrefix string

		mainContent.Find("h1.topictitle").Parent().Children().EachWithBreak(func(i int, s *goquery.Selection) bool {
			if strings.Contains(s.Text(), "prefix") {
				servicePrefix = s.Find("code").Text()
				return false
			}
			return true
		})

		if _, ok := d.definitions[servicePrefix]; !ok {
			d.definitions[servicePrefix] = &ServiceDefinition{
				Name:             title,
				Prefix:           servicePrefix,
				AuthorizationURL: filename,
			}
		}

		tables := mainContent.Find("div.table-contents table")

		actionsTable := tables.Eq(0)
		resourceTypesTable := tables.Eq(1)
		conditionKeysTable := tables.Eq(2)

		if err := d.parseActionsTable(filename, servicePrefix, actionsTable); err != nil {
			return nil, err
		}

		if err := d.parseResourceTypesTable(filename, servicePrefix, resourceTypesTable); err != nil {
			return nil, err
		}

		if err := d.parseConditionKeysTable(filename, servicePrefix, conditionKeysTable); err != nil {
			return nil, err
		}
	}

	return d, nil
}

func (d *Definitions) ServicePrefixes() []string {
	return common.MapKeys(d.definitions)
}

type GetActionsInput struct {
	ServicePrefix string
	AccessLevel   string
	NamePattern   string // supports wildcards: '*', '?'
}

func (d *Definitions) GetActions(input *GetActionsInput) []Action {
	actions := []Action{}

	prefixes := []string{input.ServicePrefix}
	if input.ServicePrefix == "" {
		prefixes = common.MapKeys(d.definitions)
	}

	for _, servicePrefix := range prefixes {
		for _, action := range d.definitions[servicePrefix].Actions {
			if input.AccessLevel != "" && input.AccessLevel != action.AccessLevel {
				continue
			}

			if input.NamePattern != "" && !common.WildcardMatch(input.NamePattern, action.Name) {
				continue
			}

			actions = append(actions, Action(fmt.Sprintf("%s:%s", servicePrefix, action.Name)))
		}
	}

	return actions
}

func (d *Definitions) Save(filename string, gzipFile bool) error {
	file, err := json.MarshalIndent(d.definitions, "", " ")
	if err != nil {
		return err
	}

	if gzipFile {
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)

		if _, err = gz.Write(file); err != nil {
			return err
		}

		if err = gz.Flush(); err != nil {
			return err
		}

		if err = gz.Close(); err != nil {
			return err
		}

		return os.WriteFile(filename, b.Bytes(), 0600)
	}

	return os.WriteFile(filename, file, 0600)
}

func (d *Definitions) parseActionsTable(filename, prefix string, table *goquery.Selection) error {
	rows := table.Find("tr")
	rowNumber := 0

	for rowNumber < rows.Length() {
		row := rows.Eq(rowNumber)

		cells := row.Find("td")
		if cells.Length() == 0 {
			// Skip header row, which has th, not td cells
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
