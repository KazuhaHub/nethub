package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/web"
)

// Synthetic counts exercise rendering and mutations only, not relay accounting.
func (r *repository) Traffic(_ context.Context, actor string, query web.TrafficQuery) (web.TrafficPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.TrafficPage{}, err
	}
	page := web.TrafficPage{Month: query.Month, InBytes: "0", OutBytes: "0", TotalBytes: "0", ResetEvents: "0", WarningRevision: r.trafficRevision, Items: []web.TrafficDevice{}}
	if r.trafficWarning != "" && r.trafficWarning != "0" {
		value := r.trafficWarning
		page.WarningBytes = &value
	}
	if query.Month != time.Now().UTC().Format("2006-01") {
		return page, nil
	}
	at := time.Now().UTC().Truncate(time.Second)
	page.InBytes, page.OutBytes, page.TotalBytes, page.ResetEvents = "9223372036854775807", "9223372036854775807", "18446744073709551614", "2"
	page.FirstObservedAt, page.LastObservedAt = &at, &at
	for i := range 52 {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", 6000+i)
		if id <= query.AfterID {
			continue
		}
		item := web.TrafficDevice{DeviceID: id, Label: fmt.Sprintf("Traffic device %02d", i), InBytes: "0", OutBytes: "0", TotalBytes: "0", ResetEvents: "0", FirstObservedAt: at, LastObservedAt: at, Removed: i == 51}
		if i == 0 {
			item.InBytes, item.OutBytes, item.TotalBytes, item.ResetEvents = page.InBytes, page.OutBytes, page.TotalBytes, page.ResetEvents
		}
		page.Items = append(page.Items, item)
	}
	if len(page.Items) > query.Limit {
		page.Items = page.Items[:query.Limit]
		next := base64.RawURLEncoding.EncodeToString([]byte(page.Items[len(page.Items)-1].DeviceID))
		page.NextCursor = &next
	}
	return page, nil
}

func (r *repository) SetTrafficWarning(_ context.Context, actor, value string, expected int64, _ netip.Addr) (web.TrafficWarning, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.invitationAdminLocked(actor); err != nil {
		return web.TrafficWarning{}, err
	}
	if expected != r.trafficRevision {
		return web.TrafficWarning{}, web.ErrTrafficChanged
	}
	previous := r.trafficWarning
	if previous == "" {
		previous = "0"
	}
	if previous != value {
		r.trafficRevision++
		r.trafficWarning = value
	}
	result := web.TrafficWarning{Revision: r.trafficRevision}
	if value != "0" {
		result.WarningBytes = &value
	}
	return result, nil
}
