package iam

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
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

func NewDefinitionsFromFS(filename string, fs fs.FS, gzipFile bool) (*Definitions, error) {
	file, err := fs.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
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
	// filenames = []string{
	// 	"https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html",
	// 	"https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazondynamodb.html",
	// 	"https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsresourceaccessmanager.html",
	// }

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
