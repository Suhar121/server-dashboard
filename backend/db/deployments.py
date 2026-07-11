import sqlite3
import json
import time
import config
from db.base import db_connect

def list_app_templates():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name, description, icon, category, compose_yaml, env_schema, default_port, created_at FROM app_templates ORDER BY category, name")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r[0], "name": r[1], "description": r[2], "icon": r[3],
            "category": r[4], "compose_yaml": r[5],
            "env_schema": json.loads(r[6]) if r[6] else [],
            "default_port": r[7], "created_at": r[8],
        }
        for r in rows
    ]

def get_app_template(template_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT id, name, description, icon, category, compose_yaml, env_schema, default_port, created_at FROM app_templates WHERE id = ?", (template_id,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r[0], "name": r[1], "description": r[2], "icon": r[3],
        "category": r[4], "compose_yaml": r[5],
        "env_schema": json.loads(r[6]) if r[6] else [],
        "default_port": r[7], "created_at": r[8],
    }

def list_deployed_apps():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""SELECT da.id, da.name, da.template_id, da.status, da.compose_path,
                          da.ports, da.env_vars, da.container_ids, da.created_by, da.created_at,
                          t.name as template_name
                   FROM deployed_apps da LEFT JOIN app_templates t ON da.template_id = t.id
                   ORDER BY da.created_at DESC""")
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r[0], "name": r[1], "template_id": r[2], "status": r[3],
            "compose_path": r[4], "ports": json.loads(r[5]) if r[5] else [],
            "env_vars": json.loads(r[6]) if r[6] else {},
            "container_ids": json.loads(r[7]) if r[7] else [],
            "created_by": r[8], "created_at": r[9], "template_name": r[10],
        }
        for r in rows
    ]

def get_deployed_app_by_name(name: str):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""SELECT da.id, da.name, da.template_id, da.status, da.compose_path,
                          da.ports, da.env_vars, da.container_ids, da.created_by, da.created_at,
                          t.name as template_name
                   FROM deployed_apps da LEFT JOIN app_templates t ON da.template_id = t.id
                   WHERE da.name = ?""", (name,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r[0], "name": r[1], "template_id": r[2], "status": r[3],
        "compose_path": r[4], "ports": json.loads(r[5]) if r[5] else [],
        "env_vars": json.loads(r[6]) if r[6] else {},
        "container_ids": json.loads(r[7]) if r[7] else [],
        "created_by": r[8], "created_at": r[9], "template_name": r[10],
    }

def get_deployed_app(app_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""SELECT da.id, da.name, da.template_id, da.status, da.compose_path,
                          da.ports, da.env_vars, da.container_ids, da.created_by, da.created_at,
                          t.name as template_name
                   FROM deployed_apps da LEFT JOIN app_templates t ON da.template_id = t.id
                   WHERE da.id = ?""", (app_id,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "id": r[0], "name": r[1], "template_id": r[2], "status": r[3],
        "compose_path": r[4], "ports": json.loads(r[5]) if r[5] else [],
        "env_vars": json.loads(r[6]) if r[6] else {},
        "container_ids": json.loads(r[7]) if r[7] else [],
        "created_by": r[8], "created_at": r[9], "template_name": r[10],
    }

def create_deployed_app(name: str, template_id: int | None, compose_path: str, ports: list, env_vars: dict, created_by: str):
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO deployed_apps (name, template_id, status, compose_path, ports, env_vars, container_ids, created_by, created_at)
           VALUES (?, ?, 'stopped', ?, ?, ?, '[]', ?, ?)""",
        (name, template_id, compose_path, json.dumps(ports), json.dumps(env_vars), created_by, now),
    )
    conn.commit()
    app_id = cur.lastrowid
    conn.close()
    return app_id

def update_deployed_app_status(app_id: int, status: str, container_ids: list | None = None):
    conn = db_connect()
    cur = conn.cursor()
    if container_ids is not None:
        cur.execute("UPDATE deployed_apps SET status = ?, container_ids = ? WHERE id = ?", (status, json.dumps(container_ids), app_id))
    else:
        cur.execute("UPDATE deployed_apps SET status = ? WHERE id = ?", (status, app_id))
    conn.commit()
    conn.close()

def delete_deployed_app(app_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM deployed_apps WHERE id = ?", (app_id,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted

def create_github_deployment(app_name, repo_url, branch, deploy_path, created_by):
    now = int(time.time())
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO github_deployments
           (app_name, repo_url, branch, compose_path, status, step_status, created_by, created_at)
           VALUES (?, ?, ?, ?, 'pending', '{}', ?, ?)""",
        (app_name, repo_url, branch, deploy_path, created_by, now),
    )
    deploy_id = cur.lastrowid
    conn.commit()
    conn.close()
    return deploy_id

def get_github_deployment(deploy_id):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM github_deployments WHERE id = ?", (deploy_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    cols = [d[0] for d in cur.description] if cur.description else []
    conn.close()
    return dict(zip(cols, row))

def get_github_deployment_by_name(app_name):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM github_deployments WHERE app_name = ?", (app_name,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    cols = [d[0] for d in cur.description] if cur.description else []
    conn.close()
    return dict(zip(cols, row))

def update_github_deployment_status(deploy_id, status, step_status=None, container_ids=None):
    conn = db_connect()
    cur = conn.cursor()
    if step_status is not None and container_ids is not None:
        cur.execute(
            "UPDATE github_deployments SET status=?, step_status=?, container_ids=? WHERE id=?",
            (status, json.dumps(step_status), json.dumps(container_ids), deploy_id),
        )
    elif step_status is not None:
        cur.execute(
            "UPDATE github_deployments SET status=?, step_status=? WHERE id=?",
            (status, json.dumps(step_status), deploy_id),
        )
    else:
        cur.execute("UPDATE github_deployments SET status=? WHERE id=?", (status, deploy_id))
    conn.commit()
    conn.close()

def update_github_deployment_fields(deploy_id, **fields):
    if not fields:
        return
    sets = []
    vals = []
    for k, v in fields.items():
        if k in ("detected_type", "detected_framework", "detected_port", "env_vars",
                 "compose_path", "logs", "container_ids", "step_status", "status"):
            sets.append(f"{k} = ?")
            vals.append(v)
    if not sets:
        return
    vals.append(deploy_id)
    conn = db_connect()
    cur = conn.cursor()
    cur.execute(f"UPDATE github_deployments SET {', '.join(sets)} WHERE id = ?", vals)
    conn.commit()
    conn.close()

def list_github_deployments():
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM github_deployments ORDER BY created_at DESC")
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description] if cur.description else []
    conn.close()
    return [dict(zip(cols, r)) for r in rows]

def delete_github_deployment(deploy_id: int):
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM github_deployments WHERE id = ?", (deploy_id,))
    deleted = cur.rowcount > 0
    conn.commit()
    conn.close()
    return deleted
