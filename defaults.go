package traefik_bot_wall

import (
	"fmt"
	"os"
)

const defaultBotDefFileName = "defaultBotDef.json"

var defaultBotDefPaths = []string{
	defaultBotDefFileName,
	"github.com/recognyze-ai/traefik-bot-wall/" + defaultBotDefFileName,
	"/plugins-local/src/github.com/recognyze-ai/traefik-bot-wall/" + defaultBotDefFileName
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
