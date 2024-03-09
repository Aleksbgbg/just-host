#[cfg(test)]
mod tests {
  use reqwest::blocking;
  use std::env;

  #[test]
  fn get_website_html() -> Result<(), reqwest::Error> {
    let website_url = format!(
      "http://{}:{}",
      env::var("HOSTNAME").unwrap_or("localhost".into()),
      env::var("PORT").unwrap_or("8601".into())
    );

    let body = blocking::get(website_url)?.text()?;

    const START: &'static str = r#"<!doctype html>
<html lang="en">
  <head>"#;
    const END: &'static str = r#"</head>
  <body>
    <div id="app"></div>
  </body>
</html>
"#;
    assert!(
      body.starts_with(START),
      "expected body to start with `{}` but was `{}`",
      START,
      body
    );
    assert!(
      body.ends_with(END),
      "expected body to end with `{}` but was `{}`",
      END,
      body
    );
    Ok(())
  }
}
