// @generated automatically by Diesel CLI.

pub mod sql_types {
  #[derive(diesel::query_builder::QueryId, diesel::sql_types::SqlType)]
  #[diesel(postgres_type(name = "authority"))]
  pub struct Authority;
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::Authority;

    users (id) {
        id -> Int8,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        username -> Text,
        email -> Text,
        password_hash -> Text,
        auth_secret -> Bytea,
        authority -> Authority,
    }
}
