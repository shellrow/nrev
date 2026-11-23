//! Bounded protocol negotiation for a directly addressed TCP service.
use super::{
    HttpProbe, Probe, ProbeConnection, ProbeContext, TlsProbe, http_status_parts, passive_greeting,
};
use crate::{error::Result, model::ProbeObservation};
use std::{future::Future, io, time::Duration};
use tokio::time::{Instant, timeout, timeout_at};

#[derive(Clone, Copy)]
pub(crate) enum WebMode {
    Unassigned,
    Http,
    Tls,
}

impl WebMode {
    pub(crate) fn for_probe(port: u16, probe: Option<&str>) -> Option<Self> {
        match probe {
            // A raw print service can interpret arbitrary application bytes as a print job.
            None if !(9100..=9107).contains(&port) => Some(Self::Unassigned),
            Some("http") => Some(Self::Http),
            Some("tls") if matches!(port, 443 | 8443) => Some(Self::Tls),
            _ => None,
        }
    }
}

pub(crate) async fn negotiate<F, Fut>(
    cached: Option<ProbeConnection>,
    mut connect: F,
    context: ProbeContext<'_>,
    mode: WebMode,
    errors: &mut Vec<String>,
) -> Result<Vec<ProbeObservation>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<ProbeConnection>>,
{
    let deadline = Instant::now() + context.timeout;
    let first = match cached {
        Some(connection) => connection,
        None => timeout_at(deadline, connect())
            .await
            .map_err(io::Error::from)??,
    };

    if matches!(mode, WebMode::Unassigned)
        && let ProbeConnection::Tcp(stream) = &first
    {
        // Peeking leaves the first byte available to the greeting parser.
        let wait = Duration::from_millis(75).min(context.timeout / 8);
        match timeout(wait, stream.peek(&mut [0; 1])).await {
            Ok(Ok(0)) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(Err(error)) => return Err(error.into()),
            Ok(Ok(_)) => {
                let greeting = timeout_at(deadline, passive_greeting(first, context))
                    .await
                    .map_err(io::Error::from)??;
                return Ok(vec![greeting]);
            }
            Err(_) => {}
        }
    }

    let (primary, secondary): (&dyn Probe, &dyn Probe) = if matches!(mode, WebMode::Tls) {
        (&TlsProbe, &HttpProbe)
    } else {
        (&HttpProbe, &TlsProbe)
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let first_budget = remaining / 2;
    let first_result = timeout(
        first_budget,
        primary.execute(
            first,
            ProbeContext {
                timeout: first_budget,
                ..context
            },
        ),
    )
    .await
    .unwrap_or_else(|elapsed| Err(io::Error::from(elapsed).into()));
    let (plain_response, first_error) = match first_result {
        Ok(observation) => {
            // Some TLS listeners answer a cleartext request with an HTTP error.
            let ambiguous = observation.evidence.iter().any(|item| {
                item.key == "status_line"
                    && matches!(
                        http_status_parts(&item.value),
                        Some((_, "400" | "426" | "497"))
                    )
            });
            if matches!(mode, WebMode::Tls) || !ambiguous {
                return Ok(vec![observation]);
            }
            (Some(observation), None)
        }
        Err(error) => (None, Some(format!("{}: {error}", primary.id()))),
    };
    let second_result = timeout_at(deadline, async {
        let connection = connect().await?;
        secondary
            .execute(
                connection,
                ProbeContext {
                    timeout: deadline.saturating_duration_since(Instant::now()),
                    ..context
                },
            )
            .await
    })
    .await
    .unwrap_or_else(|elapsed| Err(io::Error::from(elapsed).into()));
    match second_result {
        Ok(observation) => {
            if let Some(plain) = plain_response
                && observation.banner.is_none()
            {
                return Ok(vec![plain, observation]);
            }
            if matches!(mode, WebMode::Tls) {
                errors.extend(first_error);
            }
            Ok(vec![observation])
        }
        Err(error) => {
            errors.extend(first_error);
            errors.push(format!("{}: {error}", secondary.id()));
            Ok(plain_response.into_iter().collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    #[tokio::test]
    async fn cleartext_error_and_failed_tls_are_both_retained_in_either_order() {
        for mode in [WebMode::Http, WebMode::Tls] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    if buf[0] == b'G' {
                        stream
                            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .unwrap();
                    }
                }
            });
            let context = ProbeContext {
                host: "localhost",
                port: addr.port(),
                timeout: Duration::from_secs(3),
                http_body_preview_bytes: 0,
            };
            let mut errors = Vec::new();
            let observations = negotiate(
                None,
                || async { TcpStream::connect(addr).await.map(ProbeConnection::Tcp) },
                context,
                mode,
                &mut errors,
            )
            .await
            .unwrap();
            assert_eq!(observations.len(), 1);
            assert_eq!(observations[0].probe_id, "http");
            assert_eq!(errors.len(), 1);
            assert!(errors[0].starts_with("tls: TLS error:"));
            server.await.unwrap();
        }
    }
}
