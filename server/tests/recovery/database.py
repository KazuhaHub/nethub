"""Compare private database contents and grants before application writers start."""
import hashlib
import json
import re


def fingerprint(sql):
    tables = sql("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;").splitlines()
    if not tables or any(re.fullmatch('[a-z_][a-z0-9_]*', name) is None for name in tables):
        raise ValueError('Recovery database table inventory differs')
    values = []
    for name in tables:
        rows = sql('SET timezone=\'UTC\'; SET extra_float_digits=3; '
                   'SELECT to_jsonb(t)::text FROM public."' + name + '" t ORDER BY to_jsonb(t)::text;')
        values.append(('table', name, hashlib.sha256(rows.encode()).hexdigest()))
    sequences = sql("SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename;").splitlines()
    for name in sequences:
        if re.fullmatch('[a-z_][a-z0-9_]*', name) is None:
            raise ValueError('Recovery sequence name differs')
        values.append(('sequence', name, sql('SELECT last_value,is_called FROM public."' + name + '";')))
    owners = sql("SELECT jsonb_build_array(c.relname,c.relkind,pg_get_userbyid(c.relowner),"
                 "ARRAY(SELECT x FROM unnest(c.relacl) x ORDER BY x))::text "
                 "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                 "WHERE n.nspname='public' ORDER BY c.relname;")
    functions = sql("SELECT jsonb_build_array(p.oid::regprocedure::text,pg_get_userbyid(p.proowner),"
                    "p.prosecdef,ARRAY(SELECT x FROM unnest(p.proacl) x ORDER BY x))::text "
                    "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                    "WHERE n.nspname='public' ORDER BY p.oid::regprocedure::text;")
    schemas = sql("SELECT jsonb_build_array(nspname,pg_get_userbyid(nspowner),"
                  "ARRAY(SELECT x FROM unnest(nspacl) x ORDER BY x))::text "
                  "FROM pg_namespace WHERE nspname='public';")
    roles = sql("SELECT jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,"
                "rolcanlogin,rolreplication,rolbypassrls)::text FROM pg_roles "
                "WHERE rolname LIKE 'nethub_%' ORDER BY rolname;")
    memberships = sql("SELECT jsonb_build_array(pg_get_userbyid(roleid),pg_get_userbyid(member),"
                      "admin_option,inherit_option,set_option)::text FROM pg_auth_members "
                      "WHERE pg_get_userbyid(member) LIKE 'nethub_%' OR pg_get_userbyid(roleid) LIKE 'nethub_%' "
                      "ORDER BY pg_get_userbyid(roleid),pg_get_userbyid(member);")
    database = sql("SELECT jsonb_build_array(datname,pg_get_userbyid(datdba),"
                   "ARRAY(SELECT x FROM unnest(datacl) x ORDER BY x))::text "
                   "FROM pg_database WHERE datname=current_database();")
    values += [('owners', owners), ('functions', functions), ('schemas', schemas),
               ('roles', roles), ('memberships', memberships), ('database', database)]
    return hashlib.sha256(json.dumps(values, separators=(',', ':')).encode()).hexdigest()
