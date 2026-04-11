package loglog

import "strings"

// Built from common crawler identifiers used by major search engines,
// SEO crawlers, social preview bots, uptime/archival scanners, and AI crawlers.
// Matching is case-insensitive and uses substring checks.
var botUASubstrings = []string{
	"bot", "crawler", "spider", "slurp", "archiver", "transcoder", "preview", "fetcher",

	// Search engines
	"googlebot", "adsbot-google", "mediapartners-google", "apis-google", "storebot-google",
	"feedfetcher-google", "googleother", "google-inspectiontool", "bingbot", "adidxbot", "msnbot",
	"duckduckbot", "baiduspider", "yandexbot", "yandeximages", "yandexmobilebot", "yandexmetrika",
	"yahoo! slurp", "seznambot", "sogou", "exabot", "facebot", "ia_archiver", "petalbot",
	"bytespider", "qwantify", "applebot", "daumoa", "naverbot", "ccbot", "amazonbot",

	// Major SEO / link indexers
	"ahrefsbot", "ahrefs.com/robot", "dotbot", "opensiteexplorer.org/dotbot", "mj12bot", "semrushbot",
	"blexbot", "linkdexbot", "serpstatbot", "megaindex", "seokicks-robot", "seekport",
	"rogerbot", "mojeekbot", "siteauditbot", "screaming frog", "wordliftbot", "domainstatsbot",

	// Social / chat / messenger unfurlers
	"facebookexternalhit", "twitterbot", "linkedinbot", "slackbot", "discordbot", "whatsapp",
	"telegrambot", "skypeuripreview", "pinterestbot", "redditbot", "quora link preview",
	"embedly", "vkshare", "bitlybot", "tumblr", "line-poker",

	// AI crawlers and training/retrieval bots
	"gptbot", "chatgpt-user", "oai-searchbot", "claudebot", "anthropic-ai", "perplexitybot",
	"perplexity-user", "cohere-ai", "cohere-training-data-crawler", "amazon-kendra", "applebot-extended",
	"bytespider", "imagesiftbot", "diffbot", "youbot", "meta-externalagent", "meta-externalfetcher",

	// Monitoring / validators / archives / misc
	"uptimerobot", "pingdom", "statuscake", "headlesschrome", "phantomjs", "go-http-client",
	"python-requests", "curl/", "wget/", "httpclient", "okhttp", "apache-httpclient", "libwww-perl",
	"w3c_validator", "validator.nu", "archive.org_bot", "wayback", "censysinspect", "internetmeasurement",
	"masscan", "zgrab", "cloudmapping", "datadog/synthetics", "newrelicpinger", "site24x7", "check_http",
	"favicon", "rss", "feedparser", "sitemap", "nutch", "heritrix", "spbot", "zoominfobot", "magpie-crawler",
}

func isBotUserAgent(ua string) bool {
	if strings.TrimSpace(ua) == "" {
		return false
	}
	s := strings.ToLower(ua)
	for _, token := range botUASubstrings {
		if strings.Contains(s, token) {
			return true
		}
	}
	return false
}
