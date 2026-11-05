"""Mutate only an owned migration fixture to verify recovery comparison sensitivity."""
from database import capture, differing_categories, snapshot_fingerprint


def check(sql):
    original = capture(sql)
    def require_change(category):
        if category not in differing_categories(original, capture(sql)):
            raise ValueError('Changed database authority was not detected')
    sql('GRANT SELECT ON gui_certificate_applications TO nethub_web;')
    try:
        require_change('owners')
        granted = snapshot_fingerprint(capture(sql))
        sql('GRANT SELECT ON gui_certificate_applications TO nethub_web WITH GRANT OPTION;')
        if snapshot_fingerprint(capture(sql)) == granted:
            raise ValueError('Changed grant option was not detected')
    finally:
        sql('REVOKE SELECT ON gui_certificate_applications FROM nethub_web;')
    sql('REVOKE SELECT ON gui_certificate_applications FROM nethub_owner;')
    try:
        require_change('owners')
    finally:
        sql('GRANT SELECT ON gui_certificate_applications TO nethub_owner;')
    definition = sql("SELECT pg_get_constraintdef(oid,true) FROM pg_constraint "
                     "WHERE conrelid='device_rotations'::regclass "
                     "AND conname='device_rotations_credential_hash_check';")
    def install(value):
        sql('ALTER TABLE device_rotations DROP CONSTRAINT device_rotations_credential_hash_check; '
            'ALTER TABLE device_rotations ADD CONSTRAINT device_rotations_credential_hash_check ' + value)
    for before, after in (('>= 64', '>= 65'), ('$argon2id$%', '$argon2i$%'), (' AND ', ' OR ')):
        if before not in definition:
            raise ValueError('Expected migration constraint shape differs')
        install(definition.replace(before, after, 1))
        try:
            require_change('constraints')
        finally:
            install(definition)
    if snapshot_fingerprint(original) != snapshot_fingerprint(capture(sql)):
        raise ValueError('Negative controls did not restore original authority')
    return {'changed_table_grant_detected': True, 'changed_grant_option_detected': True,
            'changed_owner_privilege_detected': True, 'changed_constraint_bound_detected': True,
            'changed_constraint_prefix_detected': True, 'changed_constraint_operator_detected': True,
            'negative_controls_restored': True}
