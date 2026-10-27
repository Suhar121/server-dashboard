pub mod users;
pub mod schema;

use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};

pub type DbPool = Pool<Sqlite>;

pub async fn init_db(database_url: &str) -> Result<DbPool, sqlx::Error> {
    // If the database path is a file, ensure connection string has sqlite://
    let url = if !database_url.starts_with("sqlite:") {
        format!("sqlite:{}?mode=rwc", database_url)
    } else {
        database_url.to_string()
    };

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await?;

    // Create tables
    schema::create_tables(&pool).await?;
    schema::seed_templates(&pool).await?;

    Ok(pool)
}
