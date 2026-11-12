package main

import (
	"context"
	"fmt"
	"time"

	"github.com/KazuhaHub/nethub/server/internal/auth"
	"github.com/KazuhaHub/nethub/server/internal/web"
)

func (r *repository) Audit(_ context.Context, actor string, query web.AuditQuery) (web.AuditPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	user, ok := r.users[actor]
	if !ok || user.Disabled {
		return web.AuditPage{}, auth.ErrUnauthenticated
	}
	if query.UserID != "" && user.Role != "admin" {
		return web.AuditPage{}, web.ErrForbidden
	}
	before, err := web.AuditBefore("browser-fixture:"+actor, query)
	if err != nil {
		return web.AuditPage{}, err
	}
	page := web.AuditPage{Items: []web.AuditEntry{}}
	for sequence := int64(55); sequence > 0; sequence-- {
		if before != 0 && sequence >= before {
			continue
		}
		owner := "00000000-0000-4000-8000-000000000001"
		if sequence%2 == 0 {
			owner = "00000000-0000-4000-8000-000000000099"
		}
		if user.Role != "admin" && owner != actor {
			continue
		}
		device := "00000000-0000-4000-8000-000000000077"
		stamp := time.Date(2026, 11, 12, 0, 0, int(sequence), 0, time.UTC)
		action := "device.enrolled"
		if sequence%3 == 0 {
			action = "device.access_granted"
		}
		if (query.Action != "" && query.Action != action) || (query.DeviceID != "" && query.DeviceID != device) ||
			(query.UserID != "" && query.UserID != owner) || (query.Since != nil && stamp.Before(*query.Since)) ||
			(query.Until != nil && !stamp.Before(*query.Until)) {
			continue
		}
		if len(page.Items) == query.Limit {
			cursor := web.AuditCursor("browser-fixture:"+actor, query, sequence+1)
			page.NextCursor = &cursor
			break
		}
		ip := "203.0.113.9"
		details := web.AuditDetails{}
		if action == "device.access_granted" {
			expiry := stamp.Add(30 * time.Minute)
			details.ExpiresAt = &expiry
		}
		page.Items = append(page.Items, web.AuditEntry{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", sequence),
			CreatedAt: stamp, ActorType: "user", Actor: &owner, Action: action, TargetDeviceID: &device, ClientIP: &ip, Details: details})
	}
	return page, nil
}
