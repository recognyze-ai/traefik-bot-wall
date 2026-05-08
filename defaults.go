package botwall

import (
	"fmt"
	"os"
)

const defaultBotDefFileName = "defaultBotDef.json"

var defaultBotDefPaths = []string{
	defaultBotDefFileName,
	"r7e_botwall/" + defaultBotDefFileName,
	"github.com/recognyze-ai/bot-wall/" + defaultBotDefFileName,
	"github.com/recognyze/bot-wall/" + defaultBotDefFileName,
	"/plugins-local/src/github.com/recognyze-ai/bot-wall/" + defaultBotDefFileName,
	"/plugins-local/src/github.com/recognyze/bot-wall/" + defaultBotDefFileName,
	"plugins-local/src/recognyze/botwall/" + defaultBotDefFileName,
	"r7e_botwall/plugins-local/src/recognyze/botwall/" + defaultBotDefFileName,
	"/plugins-local/src/recognyze/botwall/" + defaultBotDefFileName,
}

func readDefaultBotDefFromFile() (botDef, error) {
	var (
		body     []byte
		pathUsed string
		lastErr  error
	)

	for _, candidate := range defaultBotDefPaths {
		content, err := os.ReadFile(candidate)
		if err == nil {
			body = content
			pathUsed = candidate
			break
		}
		lastErr = err
	}
	if pathUsed == "" {
		cwd, _ := os.Getwd()
		return botDef{}, fmt.Errorf(
			"read default bot definitions from %s failed (cwd=%s): %w",
			defaultBotDefFileName,
			cwd,
			lastErr,
		)
	}

	return parseBotDefinitionJSON(body)
}
