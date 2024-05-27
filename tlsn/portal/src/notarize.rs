// Runs a simple Prover which connects to the Notary and notarizes a request/response from
// example.com. The Prover then generates a proof and writes it to disk.

use actix_web::{http::Method, web};
use http_body_util::BodyExt;
use hyper::{client::conn::http1::SendRequest, header::{HeaderName, HeaderValue}, Request, StatusCode};
use hyper_util::rt::TokioIo;
use redis::Commands;
use serde::{Deserialize, Serialize};
use tlsn_formats::http::HttpTranscript;
use tracing::debug;
use std::{error::Error, ops::Range, str::FromStr, sync::Arc};
use tlsn_core::{commitment::CommitmentKind, proof::{SessionProof, SubstringsProofBuilder, TlsProof}, transcript, NotarizedSession};
use tokio::{io::{AsyncReadExt, AsyncWriteExt as _}, sync::Mutex};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use portal::{request_notarization, run_notary};
use tlsn_prover::tls::{state::Notarize, Prover, ProverConfig};

use crate::AppState;

const MAX_SENT_DATA: usize = 1 << 14;
const MAX_RECV_DATA: usize = 1 << 14;

#[derive(Serialize)]
pub struct NotarizedResponse {
    pub proof_file: String,
    pub raw: serde_json::Value
}

pub fn is_allowed_header(key: String) -> bool {
    let allowed_headers = [
        "authorization",
        "authentication",
        "content-type",
        "accept",
        "user-agent",
        "connection",
        "accept-encoding"
    ];
    allowed_headers.contains(&key.to_lowercase().as_str()) || key.starts_with("x-")
}

pub async fn notarize_request(data: web::Data<AppState>, method: &Method, x_request_id: String, x_host: String, x_path: String, redact: bool, raw_headers: actix_web::http::header::HeaderMap, raw_body: String) -> Result<NotarizedResponse, Box<dyn Error>> {
    let r2 = data.r2.clone();

    let notary_host = std::env::var("NOTARY_HOST").expect("init notarization server failed");
    let notary_port = std::env::var("NOTARY_PORT").expect("init notarization server failed").parse::<u16>().expect("init notarization server failed");
    
    let (notary_tls_socket, session_id) = request_notarization(
        notary_host.as_str(),
        notary_port.into(),
        Some(MAX_SENT_DATA),
        Some(MAX_RECV_DATA),
    )
    .await;

    // Basic default prover config using the session_id returned from /session endpoint just now
    let config = ProverConfig::builder()
        .id(session_id)
        .server_dns(x_host.clone())
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    // Create a new prover and set up the MPC backend.
    let prover = Prover::new(config)
        .setup(notary_tls_socket.compat())
        .await
        .unwrap();

    let client_socket = tokio::net::TcpStream::connect((x_host.clone(), 443))
        .await
        .unwrap();

    // Bind the Prover to server connection
    let (tls_connection, prover_fut) = prover.connect(client_socket.compat()).await.unwrap();

    // Spawn the Prover to be run concurrently
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(tls_connection.compat()))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers
    let mut request_builder = Request::builder()
      .uri(format!("https://{}{}", x_host, x_path))
      .method(method.as_str())
      .body(raw_body).expect("build request failed");
    
    let mut request_headers = hyper::HeaderMap::new();
    for (key, value) in raw_headers {
        if is_allowed_header(key.to_string()) {
            let key_clone = HeaderName::from_str(key.clone().as_str()).expect(&format!("Invalid header: {}", key.as_str()));
            let val_clone = HeaderValue::from_bytes(value.clone().as_bytes()).expect(&format!("Invalid header: {}", key.as_str()));
            request_headers.insert(key_clone, val_clone);
        }
        let host = HeaderValue::from_bytes(x_host.clone().as_bytes()).expect(&format!("Invalid header: {}", key.as_str()));
        request_headers.insert("host", host);
    }
    
    *request_builder.headers_mut() = request_headers;

    println!("Starting an MPC TLS connection with the server");
    // let raw_request = format!(
    //     "curl {} {} {} -d {}",
    //     request_builder.method(),
    //     request_builder.uri(),
    //     request_builder
    //         .headers()
    //         .iter()
    //         .map(|(k, v)| format!(" -H '{}: {}'", k, v.to_str().unwrap()))
    //         .collect::<String>(),
    //     request_builder.body().to_string()
    // );
    // println!("Request: {}", raw_request);

    // Send the request to the Server and get a response via the MPC TLS connection
    let response = request_sender.send_request(request_builder).await.expect("proxy request failed");

    println!("Got a response from the server {}", response.status());

    if response.status() != StatusCode::OK {
        let foo = response.into_body().collect().await.unwrap();
        println!("{:?}", foo);
        return Err("Hello".into());
        // return Err(format!("Received a status {} response message", response.status()).into());
    }

    // Pretty printing :)
    let payload = response.into_body().collect().await.unwrap().to_bytes();
    let parsed =
        serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload)).unwrap();
    debug!("{}", serde_json::to_string_pretty(&parsed).unwrap());

    // The Prover task should be done now, so we can grab it.
    let prover = prover_task.await.unwrap().unwrap();

    // Prepare for notarization
    let mut prover = prover.start_notarize();

    // Identify the ranges in the transcript that contain secrets
    let (public_ranges, private_ranges) =
        find_ranges(prover.sent_transcript().data(), &["authorization".as_bytes()]);

    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();

    // Collect commitment ids for the outbound transcript
    let mut commitment_ids = public_ranges
        .iter()
        .chain(private_ranges.iter())
        .map(|range| builder.commit_sent(range).unwrap())
        .collect::<Vec<_>>();

    // Commit to the full received transcript in one shot, as we don't need to redact anything
    commitment_ids.push(builder.commit_recv(&(0..recv_len)).unwrap());

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    debug!("Notarization complete!");

    let session_proof = notarized_session.session_proof();

    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal everything but the auth token (which was assigned commitment id 2)
    proof_builder.reveal_by_id(commitment_ids[0]).unwrap();
    proof_builder.reveal_by_id(commitment_ids[1]).unwrap();
    proof_builder.reveal_by_id(commitment_ids[3]).unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    let proof = TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };

    let file_name = format!("proof_of_{}.json", x_request_id);
    r2.upload(file_name.as_str(), serde_json::to_string_pretty(&proof).unwrap().as_bytes(), Some("immutable"), Some("multipart/form-data")).await;
    // Dump the proof to a file.
    // let mut file = tokio::fs::File::create("github_proof.json")
    //     .await
    //     .unwrap();
    // file.write_all(serde_json::to_string_pretty(&proof).unwrap().as_bytes())
    //     .await
    //     .unwrap();

    Ok(NotarizedResponse{
        proof_file: file_name,
        raw: parsed
    })
}

async fn proof_with_stackoverflow_rule(prover: tlsn_prover::http::HttpProver<tlsn_prover::http::state::Notarize>) -> TlsProof {
    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await.unwrap();

    // Dump the notarized session to a file
    // let mut file = tokio::fs::File::create("twitter_dm.json").await.unwrap();
    // file.write_all(
    //     serde_json::to_string_pretty(&notarized_session.session_proof())
    //         .unwrap()
    //         .as_bytes(),
    // )
    // .await
    // .unwrap();
    
    // println!("is ok?: {}", ok);
    let session_proof = notarized_session.session_proof();

    let mut proof_builder: SubstringsProofBuilder = notarized_session.session().data().build_substrings_proof();

    // Prove the request, while redacting the secrets from it.
    let request: &tlsn_formats::http::Request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        .unwrap();

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        .unwrap();
    for header in &request.headers {
        // Only reveal the host header
        if header.name.as_str().eq_ignore_ascii_case("Origin") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                .unwrap();
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                .unwrap();
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        .unwrap();

    // Build the proof
    let substrings_proof = proof_builder.build().unwrap();

    return TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };
}

async fn proof_with_normal_rule(prover: tlsn_prover::http::HttpProver<tlsn_prover::http::state::Notarize>) -> TlsProof {
    // Finalize, returning the notarized HTTP session
    let notarized_session = prover.finalize().await.unwrap();

    // Dump the notarized session to a file
    // let mut file = tokio::fs::File::create("twitter_dm.json").await.unwrap();
    // file.write_all(
    //     serde_json::to_string_pretty(&notarized_session.session_proof())
    //         .unwrap()
    //         .as_bytes(),
    // )
    // .await
    // .unwrap();
    
    // println!("is ok?: {}", ok);
    let session_proof = notarized_session.session_proof();

    let mut proof_builder: SubstringsProofBuilder = notarized_session.session().data().build_substrings_proof();

    // Prove the request, while redacting the secrets from it.
    let request: &tlsn_formats::http::Request = &notarized_session.transcript().requests[0];

    proof_builder
        .reveal_sent(&request.without_data(), CommitmentKind::Blake3)
        .unwrap();

    proof_builder
        .reveal_sent(&request.request.target, CommitmentKind::Blake3)
        .unwrap();
    for header in &request.headers {
        // Only reveal the host header
        if header.name.as_str().eq_ignore_ascii_case("Host") {
            proof_builder
                .reveal_sent(header, CommitmentKind::Blake3)
                .unwrap();
        } else {
            proof_builder
                .reveal_sent(&header.without_value(), CommitmentKind::Blake3)
                .unwrap();
        }
    }

    // Prove the entire response, as we don't need to redact anything
    let response = &notarized_session.transcript().responses[0];

    proof_builder
        .reveal_recv(response, CommitmentKind::Blake3)
        .unwrap();

    // Build the proof
    let substrings_proof = proof_builder.build().unwrap();

    return TlsProof {
        session: session_proof,
        substrings: substrings_proof,
    };
}
/// Find the ranges of the public and private parts of a sequence.
///
/// Returns a tuple of `(public, private)` ranges.
fn find_ranges(seq: &[u8], private_seq: &[&[u8]]) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut private_ranges = Vec::new();
    for s in private_seq {
        for (idx, w) in seq.windows(s.len()).enumerate() {
            if w == *s {
                private_ranges.push(idx..(idx + w.len()));
            }
        }
    }

    let mut sorted_ranges = private_ranges.clone();
    sorted_ranges.sort_by_key(|r| r.start);

    let mut public_ranges = Vec::new();
    let mut last_end = 0;
    for r in sorted_ranges {
        if r.start > last_end {
            public_ranges.push(last_end..r.start);
        }
        last_end = r.end;
    }

    if last_end < seq.len() {
        public_ranges.push(last_end..seq.len());
    }

    (public_ranges, private_ranges)
}

async fn build_proof_without_redactions(mut prover: Prover<Notarize>) -> TlsProof {
    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    let builder = prover.commitment_builder();
    let sent_commitment = builder.commit_sent(&(0..sent_len)).unwrap();
    let recv_commitment = builder.commit_recv(&(0..recv_len)).unwrap();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    proof_builder.reveal_by_id(sent_commitment).unwrap();
    proof_builder.reveal_by_id(recv_commitment).unwrap();

    let substrings_proof = proof_builder.build().unwrap();

    TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
    }
}

async fn build_proof_with_redactions(user_agent: String, mut prover: Prover<Notarize>) -> TlsProof {
    // Identify the ranges in the outbound data which contain data which we want to disclose
    let (sent_public_ranges, _) = find_ranges(
        prover.sent_transcript().data(),
        &[
            // Redact the value of the "User-Agent" header. It will NOT be disclosed.
            user_agent.clone().as_bytes(),
        ],
    );

    // Identify the ranges in the inbound data which contain data which we want to disclose
    let (recv_public_ranges, _) = find_ranges(
        prover.recv_transcript().data(),
        &[
            // Redact the value of the title. It will NOT be disclosed.
            "Example Domain".as_bytes(),
        ],
    );

    let builder = prover.commitment_builder();

    // Commit to each range of the public outbound data which we want to disclose
    let sent_commitments: Vec<_> = sent_public_ranges
        .iter()
        .map(|range| builder.commit_sent(range).unwrap())
        .collect();
    // Commit to each range of the public inbound data which we want to disclose
    let recv_commitments: Vec<_> = recv_public_ranges
        .iter()
        .map(|range| builder.commit_recv(range).unwrap())
        .collect();

    // Finalize, returning the notarized session
    let notarized_session = prover.finalize().await.unwrap();

    // Create a proof for all committed data in this session
    let mut proof_builder = notarized_session.data().build_substrings_proof();

    // Reveal all the public ranges
    for commitment_id in sent_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }
    for commitment_id in recv_commitments {
        proof_builder.reveal_by_id(commitment_id).unwrap();
    }

    let substrings_proof = proof_builder.build().unwrap();

    TlsProof {
        session: notarized_session.session_proof(),
        substrings: substrings_proof,
    }
}