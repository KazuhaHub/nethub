"""Compare private database contents and grants before application writers start."""
import hashlib
import json
import re


CATEGORIES = ('table', 'sequence', 'owners', 'functions', 'schemas',
              'roles', 'memberships', 'database', 'columns', 'defaults',
              'extensions', 'policies', 'constraints', 'indexes', 'role_settings')


def capture(sql):
    read = sql
    sql = lambda query: read("SET timezone='UTC'; SET extra_float_digits=3; " + query)
    tables = sql("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;").splitlines()
    if not tables or any(re.fullmatch('[a-z_][a-z0-9_]*', name) is None for name in tables):
        raise ValueError('Recovery database table inventory differs')
    values = []
    for name in tables:
        rows = sql('SELECT to_jsonb(t)::text FROM public."' + name + '" t ORDER BY to_jsonb(t)::text COLLATE "C";')
        values.append(('table', name, hashlib.sha256(rows.encode()).hexdigest()))
    sequences = sql("SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename;").splitlines()
    for name in sequences:
        if re.fullmatch('[a-z_][a-z0-9_]*', name) is None:
            raise ValueError('Recovery sequence name differs')
        values.append(('sequence', name, sql('SELECT last_value,is_called FROM public."' + name + '";')))
    owners = sql("SELECT jsonb_build_array(c.relname,c.relkind,pg_get_userbyid(c.relowner),"
                 "ARRAY(SELECT x::text FROM unnest(COALESCE(c.relacl,"
                 "acldefault(CASE WHEN c.relkind='S' THEN 's' ELSE 'r' END::\"char\",c.relowner))) x "
                 "ORDER BY x::text COLLATE \"C\"),"
                 "c.relrowsecurity,c.relforcerowsecurity)::text "
                 "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                 "WHERE n.nspname='public' ORDER BY c.relname;")
    functions = sql("SELECT jsonb_build_array(p.oid::regprocedure::text,pg_get_userbyid(p.proowner),"
                    "p.prosecdef,p.proacl IS NULL,ARRAY(SELECT x::text FROM unnest(p.proacl) x ORDER BY x::text COLLATE \"C\"),"
                    "p.proconfig,pg_get_functiondef(p.oid))::text "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                    "WHERE n.nspname='public' ORDER BY p.oid::regprocedure::text;")
    schemas = sql("SELECT jsonb_build_array(nspname,pg_get_userbyid(nspowner),"
                  "nspacl IS NULL,ARRAY(SELECT x::text FROM unnest(nspacl) x ORDER BY x::text COLLATE \"C\"))::text "
                  "FROM pg_namespace WHERE nspname='public';")
    roles = sql("SELECT jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
                "rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolvaliduntil,rolconfig)::text FROM pg_roles "
                "WHERE rolname LIKE 'nethub_%' ORDER BY rolname;")
    memberships = sql("SELECT jsonb_build_array(pg_get_userbyid(roleid),pg_get_userbyid(member),"
                      "admin_option,inherit_option,set_option)::text FROM pg_auth_members "
                      "WHERE pg_get_userbyid(member) LIKE 'nethub_%' OR pg_get_userbyid(roleid) LIKE 'nethub_%' "
                      "ORDER BY pg_get_userbyid(roleid),pg_get_userbyid(member);")
    database = sql("SELECT jsonb_build_array(datname,pg_get_userbyid(datdba),"
                   "datacl IS NULL,ARRAY(SELECT x::text FROM unnest(datacl) x ORDER BY x::text COLLATE \"C\"),"
                   "datallowconn,datconnlimit,datcollate,datctype)::text "
                   "FROM pg_database WHERE datname=current_database();")
    columns = sql("SELECT jsonb_build_array(c.relname,a.attname,a.atttypid::regtype::text,a.atttypmod,"
                  "a.attnotnull,a.attidentity,a.attgenerated,pg_get_expr(d.adbin,d.adrelid),a.attacl IS NULL,"
                  "ARRAY(SELECT x::text FROM unnest(a.attacl) x ORDER BY x::text COLLATE \"C\"))::text "
                  "FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                  "LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum "
                  "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped "
                  "ORDER BY c.relname,a.attnum;")
    defaults = sql("SELECT jsonb_build_array(pg_get_userbyid(d.defaclrole),n.nspname,d.defaclobjtype,"
                   "ARRAY(SELECT x::text FROM unnest(d.defaclacl) x ORDER BY x::text COLLATE \"C\"))::text "
                   "FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace "
                   "ORDER BY pg_get_userbyid(d.defaclrole),n.nspname,d.defaclobjtype;")
    extensions = sql("SELECT jsonb_build_array(e.extname,e.extversion,pg_get_userbyid(e.extowner),n.nspname,"
                     "e.extrelocatable,ARRAY(SELECT x::regclass::text FROM unnest(e.extconfig) x),e.extcondition)::text "
                     "FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace ORDER BY e.extname;")
    policies = sql("SELECT jsonb_build_array(c.relname,p.polname,p.polcmd,p.polpermissive,"
                   "ARRAY(SELECT CASE WHEN x=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x)::text END "
                   "FROM unnest(p.polroles) x ORDER BY CASE WHEN x=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x)::text END COLLATE \"C\"),"
                   "pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid))::text "
                   "FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                   "WHERE n.nspname='public' ORDER BY c.relname,p.polname;")
    constraints = sql("SELECT jsonb_build_array(c.relname,k.conname,k.contype,k.convalidated,k.condeferrable,"
                      "k.condeferred,pg_get_constraintdef(k.oid,true))::text FROM pg_constraint k "
                      "JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace "
                      "WHERE n.nspname='public' ORDER BY c.relname,k.conname;")
    indexes = sql("SELECT jsonb_build_array(c.relname,pg_get_indexdef(i.indexrelid),i.indisvalid,i.indisready,"
                  "i.indisunique,i.indnullsnotdistinct)::text FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid "
                  "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' "
                  "ORDER BY c.relname,pg_get_indexdef(i.indexrelid);")
    role_settings = sql("SELECT jsonb_build_array(CASE WHEN s.setrole=0 THEN 'ALL' ELSE pg_get_userbyid(s.setrole)::text END,"
                        "s.setconfig)::text FROM pg_db_role_setting s "
                        "WHERE s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()) "
                        "ORDER BY s.setrole=0,pg_get_userbyid(s.setrole)::text;")
    values += [('owners', owners), ('functions', functions), ('schemas', schemas),
               ('roles', roles), ('memberships', memberships), ('database', database),
               ('columns', columns), ('defaults', defaults), ('extensions', extensions),
               ('policies', policies), ('constraints', constraints), ('indexes', indexes),
               ('role_settings', role_settings)]
    return values


def snapshot_fingerprint(values):
    return hashlib.sha256(json.dumps(values, separators=(',', ':')).encode()).hexdigest()


def fingerprint(sql):
    return snapshot_fingerprint(capture(sql))


def differing_categories(expected, actual):
    def grouped(values):
        result = {name: [] for name in CATEGORIES}
        for value in values:
            if not value or value[0] not in result:
                raise ValueError('Unexpected recovery database category')
            result[value[0]].append(value)
        return result
    before, after = grouped(expected), grouped(actual)
    return [name for name in CATEGORIES if before[name] != after[name]]


DETAIL_FIELDS = {
    'owners': (1, ('name', 'kind', 'owner', 'acl', 'rls', 'force_rls')),
    'extensions': (1, ('name', 'version', 'owner', 'schema', 'relocatable', 'tables', 'conditions')),
    'constraints': (2, ('table', 'name', 'kind', 'validated', 'deferrable', 'deferred', 'definition')),
}


def difference_details(expected, actual):
    """Expose fixed field identifiers, never an object identity or field value."""
    changed = differing_categories(expected, actual)
    result = {}
    for category in changed:
        if category not in DETAIL_FIELDS:
            continue
        key_size, fields = DETAIL_FIELDS[category]
        def rows(values):
            entry = [value for value in values if value[0] == category]
            if len(entry) != 1 or len(entry[0]) != 2:
                raise ValueError('Unexpected recovery database detail layout')
            mapped = {}
            for line in entry[0][1].splitlines():
                try:
                    row = json.loads(line)
                    if not isinstance(row, list) or len(row) != len(fields):
                        raise ValueError
                    key = tuple(row[:key_size])
                    if key in mapped:
                        raise ValueError
                    mapped[key] = row
                except (TypeError, ValueError):
                    raise ValueError('Unexpected recovery database detail layout') from None
            return mapped
        before, after = rows(expected), rows(actual)
        shared = before.keys() & after.keys()
        result[category] = {
            'missing_objects': bool(before.keys() - after.keys()),
            'extra_objects': bool(after.keys() - before.keys()),
            'fields': [name for index, name in enumerate(fields)
                       if any(before[key][index] != after[key][index] for key in shared)],
        }
    return result
