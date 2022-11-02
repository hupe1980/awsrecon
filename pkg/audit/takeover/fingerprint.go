package takeover

// https://github.com/EdOverflow/can-i-take-over-xyz

type Fingerprint struct {
	Service     string
	CName       []string
	Fingerprint []string
}

var DefaultFingerprints = []Fingerprint{
	{
		Service:     "aws s3",
		CName:       []string{"amazonaws"},
		Fingerprint: []string{"The specified bucket does not exist"},
	},
	{
		Service: "aws elastic beanstalk",
		CName: []string{
			".azurewebsites.net",
			".cloudapp.net",
			".cloudapp.azure.com",
			".trafficmanager.net",
			".blob.core.windows.net",
			".azure-api.net",
			".azurehdinsight.net",
			".azureedge.net"},
		Fingerprint: []string{},
	},
	{
		Service:     "azure",
		CName:       []string{"elasticbeanstalk"},
		Fingerprint: []string{"404 Not Found"},
	},
	{
		Service:     "bitbucket",
		CName:       []string{"bitbucket.io"},
		Fingerprint: []string{"Repository not found"},
	},
	{
		Service:     "github",
		CName:       []string{"github.io"},
		Fingerprint: []string{"There isn't a GitHub Pages site here."},
	},
	{
		Service:     "heroku",
		CName:       []string{"herokuapp"},
		Fingerprint: []string{"herokucdn.com/error-pages/no-such-app.html"},
	},
	{
		Service:     "wordpress",
		CName:       []string{"wordpress.com"},
		Fingerprint: []string{"Do you want to register"},
	},
}
