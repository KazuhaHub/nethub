package relaystate

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/KazuhaHub/nethub/server/internal/boundedjson"
	"github.com/KazuhaHub/nethub/server/internal/relayhook"
)

var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var subdomain = regexp.MustCompile(`^[a-z0-9]{8}$`)

func (o Observation) Valid() bool {
	return uuid.MatchString(o.DeviceID) && subdomain.MatchString(o.Subdomain)
}

func parse(reader io.Reader) ([]Observation, error) {
	object, err := boundedjson.ObjectWithLimits(reader, maxBody, MaxProxies)
	if err != nil {
		return nil, ErrResponse
	}
	var proxies []map[string]json.RawMessage
	data, present := object["proxies"]
	if !present || null(data) || json.Unmarshal(data, &proxies) != nil || len(proxies) > MaxProxies {
		return nil, ErrResponse
	}
	seen := map[string]bool{}
	observations := make([]Observation, 0, len(proxies))
	for _, proxy := range proxies {
		name, validName := text(proxy, "name")
		status, validStatus := text(proxy, "status")
		if !validName || name == "" || len(name) > 512 || seen[name] || !validStatus || status != "online" && status != "offline" {
			return nil, ErrResponse
		}
		seen[name] = true
		if status == "offline" {
			continue
		}
		deviceID := strings.TrimSuffix(strings.TrimPrefix(name, "nethub-"), "-web")
		if !uuid.MatchString(deviceID) || name != relayhook.ProxyName(deviceID) {
			continue
		}
		var config map[string]json.RawMessage
		if json.Unmarshal(proxy["conf"], &config) != nil || config == nil {
			return nil, ErrResponse
		}
		configName, validName := text(config, "name")
		kind, validType := text(config, "type")
		assigned, validDomain := text(config, "subdomain")
		if !validName || configName != name || !validType || kind != "https" || !validDomain || !subdomain.MatchString(assigned) {
			return nil, ErrResponse
		}
		if domains, present := config["customDomains"]; present {
			var values []string
			if json.Unmarshal(domains, &values) != nil || len(values) != 0 {
				return nil, ErrResponse
			}
		}
		if loadBalancer, present := config["loadBalancer"]; present {
			var group map[string]json.RawMessage
			if json.Unmarshal(loadBalancer, &group) != nil || group == nil {
				return nil, ErrResponse
			}
			for _, key := range []string{"group", "groupKey"} {
				if _, present := group[key]; present {
					if value, ok := text(group, key); !ok || value != "" {
						return nil, ErrResponse
					}
				}
			}
		}
		observations = append(observations, Observation{DeviceID: deviceID, Subdomain: assigned})
	}
	return observations, nil
}

func null(data []byte) bool { return bytes.Equal(bytes.TrimSpace(data), []byte("null")) }

func text(object map[string]json.RawMessage, key string) (string, bool) {
	data, present := object[key]
	var value string
	if !present || null(data) || json.Unmarshal(data, &value) != nil {
		return "", false
	}
	return value, true
}
