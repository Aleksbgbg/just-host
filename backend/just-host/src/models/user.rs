use crate::models::id::Id;
use crate::models::schema::users;
use crate::snowflake::SnowflakeGenerator;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use diesel::pg::Pg;
use diesel::sql_types::VarChar;
use diesel::{
  sql_function, Insertable, OptionalExtension, QueryDsl, Queryable, Selectable, SelectableHelper,
  TextExpressionMethods,
};
use diesel_async::pooled_connection::deadpool::{Pool, PoolError};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use diesel_derive_enum::DbEnum;
use thiserror::Error;

sql_function!(fn lower(x: VarChar) -> VarChar);

#[derive(Clone, Copy, PartialEq, Eq, Debug, DbEnum)]
#[ExistingTypePath = "crate::models::schema::sql_types::Authority"]
pub enum Authority {
  Owner,
  Admin,
  None,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(Pg))]
pub struct User {
  pub id: Id,
  pub username: String,
  pub email: String,
  pub password: String,
  pub authority: Authority,
}

#[derive(Error, Debug)]
pub enum DatabaseError {
  #[error(transparent)]
  Pool(#[from] PoolError),
  #[error(transparent)]
  Database(#[from] diesel::result::Error),
}

pub async fn name_exists(
  pool: &Pool<AsyncPgConnection>,
  username: &str,
) -> Result<bool, DatabaseError> {
  Ok(
    users::table
      .select(users::id)
      .filter(lower(users::username).like(username.to_lowercase()))
      .first::<i64>(&mut pool.get().await?)
      .await
      .optional()?
      .is_some(),
  )
}

pub async fn email_exists(
  pool: &Pool<AsyncPgConnection>,
  email: &str,
) -> Result<bool, DatabaseError> {
  Ok(
    users::table
      .select(users::id)
      .filter(lower(users::email).like(email.to_lowercase()))
      .first::<i64>(&mut pool.get().await?)
      .await
      .optional()?
      .is_some(),
  )
}

#[derive(Insertable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(Pg))]
struct NewUser<'a> {
  id: Id,
  username: &'a str,
  email: &'a str,
  password: &'a str,
  authority: Authority,
}

pub struct CreateUser<'a> {
  pub username: &'a str,
  pub email: &'a str,
  pub password: &'a str,
  pub authority: Authority,
}

#[derive(Error, Debug)]
pub enum CreateUserError {
  #[error(transparent)]
  Pool(#[from] PoolError),
  #[error(transparent)]
  Database(#[from] diesel::result::Error),
  #[error("could not hash password")]
  HashPassword,
  #[error(transparent)]
  GenerateUserSecret(#[from] rand_core::Error),
}

pub async fn create(
  pool: &Pool<AsyncPgConnection>,
  snowflake: &SnowflakeGenerator,
  user: CreateUser<'_>,
) -> Result<User, CreateUserError> {
  let id = Id::from(snowflake.generate_id().await);
  let password = Argon2::default()
    .hash_password(user.password.as_bytes(), &SaltString::generate(&mut OsRng))
    .map_err(|_| CreateUserError::HashPassword)?
    .to_string();

  Ok(
    diesel::insert_into(users::table)
      .values(&NewUser {
        id,
        username: user.username,
        email: user.email,
        password: &password,
        authority: user.authority,
      })
      .returning(User::as_returning())
      .get_result(&mut pool.get().await?)
      .await?,
  )
}
