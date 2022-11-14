# Enumerate environment variables
```
Usage:
  awsrecon envs [flags]

Flags:
  -e, --entropy float                  minimum entropy
  -h, --help                           help for envs
      --high-entropy-threshold float   high entropy threshold (default 3.5)
      --ignore-service strings         ignore services when enumeration
      --verify                         verify secrets

Global Flags:
  -o, --output string       output filename
      --profile string      AWS profile
      --region strings      AWS regions (default all aws regions)
  -A, --user-agent string   user-agent to use (default "awsrecon")
```
## Output
```
 _____ _ _ _ _____
|  _  | | | |   __|___ ___ ___ ___ ___
|     | | | |__   |  _| -_|  _| . |   |
|__|__|_____|_____|_| |___|___|___|_|_|

[i] Enumerating environment variables for account 12345678910
[i] Enumerating apprunner done [==========] 100 %
[i] Enumerating codebuild done [==========] 100 %
[i] Enumerating ecs done [==========] 100 %
[i] Enumerating lambda done [==========] 100 %
[i] Enumerating lightsail done [==========] 100 %
[i] Enumerating sagemaker-processing done [==========] 100 %
[i] Enumerating sagemaker-transform done [==========] 100 %
[i] Enumerating sagemaker-training done [==========] 100 %
```
|Service|Region|Name|Key|Value|Entropy|Hints
|-|-|-|-|-|-|-
|Lambda|us-west-1|demo-function|SLACK_BOT_TOKEN|xoxb-510...-525...-CUq...|4.251560|SlackBotToken, HighEntropy
```
[i] 1 environment variables enumerated.
```
