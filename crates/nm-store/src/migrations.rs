use crate::Result;
use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};

pub fn apply(connection: &mut Connection) -> Result<()> {
    Migrations::new(vec![M::up(include_str!("../migrations/0001_initial.sql"))])
        .to_latest(connection)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initial_schema_is_complete_and_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply(&mut conn).unwrap();
        apply(&mut conn).unwrap();
        let tables: i64 = conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", [], |r| r.get(0)).unwrap();
        assert_eq!(tables, 14);
        assert_eq!(
            conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        conn.execute("INSERT INTO audit_log (ts,actor,action,target,detail_json,bytes_out,bytes_in) VALUES ('2026-10-06T00:00:00Z','\"System\"','\"DryRun\"','test','{}',0,0)", []).unwrap();
        assert!(conn.execute("DELETE FROM audit_log", []).is_err());
        assert!(conn
            .execute("UPDATE audit_log SET target='changed'", [])
            .is_err());
    }
}
