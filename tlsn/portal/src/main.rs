mod notarize;
mod r2_utils;

use actix_web::{get, http::{header::{self, HeaderValue}, Method, StatusCode}, web, App, HttpRequest, HttpServer, Responder, Result};
use serde::Serialize;
use serde_json::{json, Value};
use notarize::{notarize_request, NotarizedResponse};
use dotenv;
use tokio::io::AsyncWriteExt;

pub struct AppState {
  pub r2: r2_utils::R2Manager,
}
#[derive(Serialize)]
struct ResponsePayload {
  status: u16,
  message: String,
  request_id: String,
  data: Option<NotarizedResponse>
}

async fn greet() -> &'static str {
  "Hello world!"
}

async fn notarize(data: web::Data<AppState>, _req: HttpRequest, bytes: web::Bytes) -> Result<impl Responder> {
  let mut raw_headers = _req.headers().clone();
  let mut method = Method::GET;
  let mut redact = false;

  let x_method = raw_headers.get("x-tlsn-method").unwrap_or(&HeaderValue::from(0)).to_str().unwrap_or("").to_string();
  if x_method != "0" {
    method = Method::from_bytes(x_method.as_bytes()).expect("invalid method");
  }

  let x_redact = raw_headers.get("x-tlsn-path").unwrap_or(&HeaderValue::from(0)).to_str().unwrap_or("").to_string();
  if x_redact == "true" {
    redact = true;
  }

  let x_request_id = raw_headers.get("x-tlsn-request-id").unwrap_or(&HeaderValue::from(0)).to_str().unwrap_or("").to_string();
  if x_request_id == "0" {
    return Ok(web::Json(ResponsePayload {
      status: StatusCode::BAD_REQUEST.as_u16(),
      message: "invalid header: x-tlsn-request-id".to_string(),
      request_id: "".to_string(),
      data: None,
    }));
  }

  let x_path = raw_headers.get("x-tlsn-path").unwrap_or(&HeaderValue::from(0)).to_str().unwrap_or("").to_string();
  if x_path == "0" {
    return Ok(web::Json(ResponsePayload {
      status: StatusCode::BAD_REQUEST.as_u16(),
      message: "invalid header: x-tlsn-path".to_string(),
      request_id: "".to_string(),
      data: None,
    }));
  }

  let x_host = raw_headers.get("x-tlsn-host").unwrap_or(&HeaderValue::from(0)).to_str().unwrap_or("").to_string();
  if x_host == "0" {
    return Ok(web::Json(ResponsePayload {
      status: StatusCode::BAD_REQUEST.as_u16(),
      message: "invalid header: host".to_string(),
      request_id: "".to_string(),
      data: None,
    }));
  }

  raw_headers.append(header::ACCEPT_ENCODING, HeaderValue::from_static("identity"));
  raw_headers.append(header::CONNECTION, HeaderValue::from_static("close"));

  let raw_body = String::from_utf8(bytes.to_vec()).expect("no body");

  match notarize_request(data, &method, x_request_id.clone(), x_host.clone(), x_path.clone(), redact, raw_headers, raw_body).await {
    Ok(data) => Ok(web::Json(ResponsePayload {
      status: StatusCode::OK.as_u16(),
      message: "success".to_string(),
      request_id: x_request_id,
      data: Some(data),
    })),
    Err(error) => Ok(web::Json(ResponsePayload {
      status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
      message: error.to_string(),
      request_id: x_request_id,
      data: None,
    }))
  }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
  dotenv::dotenv().ok();
  env_logger::init();

  let host = std::env::var("API_HOST").expect("missing API_HOST");
  let port = std::env::var("API_PORT").expect("missing API_PORT").parse::<u16>().expect("invalid API_PORT");

  let r2 = r2_utils::R2Manager::new().await;

  println!("Connected to R2 bucket {}", r2.get_bucket_name());
  HttpServer::new(move || {
    App::new()
    .app_data(web::Data::new(AppState {
      r2: r2.clone()
    }))
    .route("/", web::get().to(greet))
    .route("/notarize", web::post().to(notarize))
  })
  .bind((host, port))?
  .run()
  .await
}