package store

import (
	"context"
	"database/sql"

	"github.com/KazuhaHub/nethub/server/internal/device"
	"github.com/KazuhaHub/nethub/server/internal/guicert"
)

// GUIJobQueue admits initial work only for an authenticated live assignment.
// It does not create an account, perform CA operations or enable background work.
type GUIJobQueue struct{ Requests *GUIRequestStore }

func (s *GUIJobQueue) Settings(ctx context.Context, credential device.Credential, id string) (guicert.Assignment, *GUIRequest, error) {
	if s == nil || s.Requests == nil {
		return guicert.Assignment{}, nil, device.ErrUnavailable
	}
	return s.Requests.Settings(ctx, credential, id)
}

// Admit commits the original signed request, initial job and their audits in
// one assignment-locked transaction. An identical retry retains generation one.
func (s *GUIJobQueue) Admit(ctx context.Context, credential device.Credential, id string, encoded []byte) (GUIRequest, error) {
	if s == nil || s.Requests == nil {
		return GUIRequest{}, device.ErrUnavailable
	}
	return s.Requests.admit(ctx, credential, id, encoded, true)
}

func (s *GUIJobQueue) Health(ctx context.Context) error {
	if s == nil || s.Requests == nil || s.Requests.Health(ctx) != nil {
		return device.ErrUnavailable
	}
	var ready bool
	err := s.Requests.Enrollment.DB.QueryRowContext(ctx, `SELECT
 has_function_privilege(current_user,'public.enqueue_gui_certificate_request(uuid)','EXECUTE')
 AND has_function_privilege(current_user,'public.record_gui_certificate_application(uuid,uuid,text,text,uuid,integer,text)','EXECUTE')
 AND EXISTS (SELECT FROM pg_proc WHERE oid='public.record_gui_certificate_application(uuid,uuid,text,text,uuid,integer,text)'::regprocedure
   AND prosecdef AND proowner='nethub_owner'::regrole)
 AND NOT has_table_privilege(current_user,'public.gui_certificate_applications','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT has_any_column_privilege(current_user,'public.gui_certificate_applications','SELECT,INSERT,UPDATE,REFERENCES')
 AND EXISTS (SELECT FROM pg_class WHERE oid='public.gui_certificate_applications'::regclass AND relrowsecurity AND relforcerowsecurity)
 AND EXISTS (SELECT FROM pg_trigger WHERE tgrelid='public.gui_certificate_applications'::regclass
   AND tgname='gui_certificate_application_immutable' AND NOT tgisinternal AND tgenabled IN ('O','A')
   AND tgfoid='public.retain_gui_certificate_application()'::regprocedure)
 AND has_function_privilege(current_user,'public.read_issued_gui_certificate(uuid,uuid,text,text)','EXECUTE')
 AND EXISTS (SELECT FROM pg_proc WHERE oid='public.read_issued_gui_certificate(uuid,uuid,text,text)'::regprocedure
   AND prosecdef AND proowner='nethub_owner'::regrole)
 AND NOT has_table_privilege(current_user,'public.gui_certificate_generations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT has_any_column_privilege(current_user,'public.gui_certificate_generations','SELECT,INSERT,UPDATE,REFERENCES')
 AND EXISTS (SELECT FROM pg_class WHERE oid='public.gui_certificate_generations'::regclass AND relrowsecurity AND relforcerowsecurity)
 AND EXISTS (SELECT FROM pg_trigger WHERE tgrelid='public.gui_certificate_generations'::regclass
   AND tgname='gui_certificate_generation_immutable' AND NOT tgisinternal AND tgenabled IN ('O','A')
   AND tgfoid='public.retain_gui_certificate_generation()'::regprocedure)
 AND NOT has_table_privilege(current_user,'public.gui_certificate_jobs','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 AND NOT has_any_column_privilege(current_user,'public.gui_certificate_jobs','SELECT,INSERT,UPDATE,REFERENCES')
 AND EXISTS (SELECT 1 FROM pg_class WHERE oid='public.gui_certificate_jobs'::regclass AND relrowsecurity AND relforcerowsecurity)
 AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.gui_certificate_jobs'::regclass
   AND tgname='gui_certificate_job_identity' AND NOT tgisinternal AND tgenabled IN ('O','A')
   AND tgfoid='public.guard_gui_certificate_job_identity()'::regprocedure)
 AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.devices'::regclass
   AND tgname='devices_cancel_gui_jobs' AND NOT tgisinternal AND tgenabled IN ('O','A')
   AND tgfoid='public.cancel_changed_gui_certificate_jobs()'::regprocedure)`).Scan(&ready)
	if err != nil || !ready {
		return device.ErrUnavailable
	}
	return nil
}

func (s *GUIJobQueue) Enqueue(ctx context.Context, credential device.Credential, id string) (string, error) {
	if s == nil || s.Requests == nil {
		return "", device.ErrUnavailable
	}
	tx, host, key, err := s.Requests.lock(ctx, credential, id)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	request, found, err := readGUIRequest(ctx, tx, credential.TenantID, id, host, key)
	if err != nil {
		return "", err
	}
	if !found {
		return "", device.ErrDenied
	}
	job, err := enqueueGUIRequest(ctx, tx, request.ID)
	if err != nil {
		return "", err
	}
	if tx.Commit() != nil {
		return "", device.ErrUnavailable
	}
	return job, nil
}

func enqueueGUIRequest(ctx context.Context, tx *sql.Tx, requestID string) (string, error) {
	var job sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT enqueue_gui_certificate_request($1)`, requestID).Scan(&job); err != nil {
		return "", device.ErrUnavailable
	}
	if !job.Valid {
		return "", device.ErrDenied
	}
	return job.String, nil
}
