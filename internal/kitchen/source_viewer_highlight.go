// Copyright (C) 2026 boostsecurity.io
// SPDX-License-Identifier: AGPL-3.0-or-later

package kitchen

import (
	"html"
	"html/template"
	"path/filepath"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
)

func sourceViewerHighlightedLines(content, path string) []template.HTML {
	lexer := sourceViewerLexer(content, path)
	iterator, err := lexer.Tokenise(nil, content)
	if err != nil {
		return nil
	}
	tokenLines := chroma.SplitTokensIntoLines(iterator.Tokens())
	lines := make([]template.HTML, 0, len(tokenLines))
	for _, tokens := range tokenLines {
		var b strings.Builder
		for _, token := range tokens {
			value := strings.TrimSuffix(token.Value, "\n")
			if value == "" {
				continue
			}
			escaped := html.EscapeString(value)
			if cls := sourceViewerChromaClass(token.Type); cls != "" {
				b.WriteString(`<span class="`)
				b.WriteString(cls)
				b.WriteString(`">`)
				b.WriteString(escaped)
				b.WriteString(`</span>`)
			} else {
				b.WriteString(escaped)
			}
		}
		if b.Len() == 0 {
			b.WriteString(" ")
		}
		lines = append(lines, template.HTML(b.String()))
	}
	if len(lines) > 1 && strings.TrimSpace(string(lines[len(lines)-1])) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func sourceViewerLexer(content, path string) chroma.Lexer {
	lexer := lexers.Match(path)
	if lexer == nil {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yml", ".yaml":
			lexer = lexers.Get("yaml")
		case ".json":
			lexer = lexers.Get("json")
		case ".sh", ".bash":
			lexer = lexers.Get("bash")
		case ".go":
			lexer = lexers.Get("go")
		}
	}
	if lexer == nil {
		lexer = lexers.Fallback
	}
	return chroma.Coalesce(lexer)
}

func sourceViewerChromaClass(tokenType chroma.TokenType) string {
	for tokenType != 0 {
		if cls, ok := chroma.StandardTypes[tokenType]; ok && cls != "" {
			return "ch-" + cls
		}
		tokenType = tokenType.Parent()
	}
	if cls, ok := chroma.StandardTypes[tokenType]; ok && cls != "" {
		return "ch-" + cls
	}
	return ""
}
