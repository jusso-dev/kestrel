//! Desired configuration polling, live check schedules and local exposition.

use crate::{buffer::Buffer, config::AgentConfigFile, desired, shipper::Shipper};
use kestrel_checks::{Collector, HttpCheck};
use kestrel_proto::{v1, Sample};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};

pub type Latest = Arc<Mutex<BTreeMap<String, Sample>>>;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub async fn forward_samples(
    mut rx: mpsc::Receiver<Vec<Sample>>,
    tx: mpsc::Sender<Vec<Sample>>,
    latest: Latest,
) {
    while let Some(samples) = rx.recv().await {
        {
            let mut view = latest.lock().unwrap_or_else(|err| err.into_inner());
            for sample in &samples {
                let mut labels = sample.labels.clone();
                labels.sort();
                let key = format!("{}{:?}", sample.name, labels);
                view.insert(key, sample.clone());
            }
            // Disappeared entities must not remain exposed forever.
            let cutoff = now_ms() - 20 * 60 * 1000;
            view.retain(|_, sample| sample.timestamp_ms >= cutoff);
        }
        if tx.send(samples).await.is_err() {
            break;
        }
    }
}

pub async fn serve_metrics(
    addr: &str,
    latest: Latest,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let addr: std::net::SocketAddr = addr.parse().or_else(|err| {
        addr.strip_prefix("localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .map(|port| std::net::SocketAddr::from(([127, 0, 0, 1], port)))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
    })?;
    if !addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Prometheus listener must be loopback",
        ));
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = axum::Router::new().route(
        "/metrics",
        axum::routing::get(move || {
            let latest = latest.clone();
            async move {
                let samples: Vec<Sample> = latest
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .values()
                    .cloned()
                    .collect();
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4; charset=utf-8",
                    )],
                    kestrel_checks::encode_exposition(&samples),
                )
            }
        }),
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
}

pub async fn poll_config(
    cfg: AgentConfigFile,
    shipper: Arc<Shipper>,
    tx: mpsc::Sender<Vec<Sample>>,
    buffer: Arc<Mutex<Buffer>>,
    agent_id: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut etag = String::new();
    let mut active = schedule(
        &cfg,
        v1::AgentConfig::default(),
        tx.clone(),
        buffer.clone(),
        agent_id.clone(),
        shutdown.clone(),
    );
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.config_poll_s.clamp(1, 60)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = ticker.tick() => {
                let mut request = shipper.client().get(desired::config_url(&cfg.server_url));
                if !etag.is_empty() { request = request.header(reqwest::header::IF_NONE_MATCH, &etag); }
                let fetched = tokio::select! {
                    _ = shutdown.changed() => break,
                    response = request.send() => response,
                };
                match fetched {
                    Ok(response) if response.status() == reqwest::StatusCode::NOT_MODIFIED => {},
                    Ok(response) if response.status().is_success() => {
                        let next_etag = response.headers().get(reqwest::header::ETAG).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                        match response.json::<v1::AgentConfig>().await {
                            Ok(config) => {
                                for task in active.drain(..) { let task: tokio::task::JoinHandle<()> = task; task.abort(); let _ = task.await; }
                                active = schedule(&cfg, config, tx.clone(), buffer.clone(), agent_id.clone(), shutdown.clone());
                                etag = next_etag;
                            }
                            Err(err) => tracing::warn!(error=%err, "invalid desired configuration"),
                        }
                    },
                    Ok(response) => tracing::warn!(status=%response.status(), "desired configuration request failed"),
                    Err(err) => tracing::warn!(error=%err, "desired configuration request failed"),
                }
            }
        }
    }
    for task in active {
        task.abort();
        let _ = task.await;
    }
}

fn append(buffer: &Mutex<Buffer>, mut batch: v1::Batch, agent_id: &str) -> bool {
    batch.agent_id = agent_id.to_string();
    if let Err(err) = buffer
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .append(&batch)
    {
        tracing::warn!(error=%err, "could not buffer check result");
        return false;
    }
    true
}

fn schedule(
    cfg: &AgentConfigFile,
    mut config: v1::AgentConfig,
    tx: mpsc::Sender<Vec<Sample>>,
    buffer: Arc<Mutex<Buffer>>,
    agent_id: String,
    shutdown: watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut tasks = Vec::new();
    if !config.logs.is_empty() {
        let saved = kestrel_checks::load_log_offsets(&cfg.data_dir).unwrap_or_default();
        let mut tailers: Vec<_> = config
            .logs
            .iter()
            .filter_map(|spec| {
                match kestrel_checks::LogTailer::open(&spec.path, Some(&spec.pattern)) {
                    Ok(mut tailer) => {
                        tailer.apply_saved_offsets(&saved);
                        Some(tailer)
                    }
                    Err(err) => {
                        tracing::warn!(error=%err,"invalid log configuration");
                        None
                    }
                }
            })
            .collect();
        let dir = cfg.data_dir.clone();
        let buffer = buffer.clone();
        let id = agent_id.clone();
        let mut stop = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick=tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut pending = Vec::new();
            loop {tokio::select! {
                _=stop.changed()=>break,
                _=tick.tick()=> {
                    if pending.is_empty() {
                        for tailer in &mut tailers {match tailer.poll(now_ms()) {Ok(logs)=>pending.extend(logs),Err(err)=>tracing::warn!(error=%err,"log tail failed")}}
                    }
                    if pending.is_empty() || append(&buffer,v1::Batch{logs:pending.clone(),..Default::default()},&id) {
                        pending.clear();
                        if let Err(err)=kestrel_checks::save_log_offsets(&dir,&tailers) {tracing::warn!(error=%err,"could not checkpoint logs");}
                    }
                }
            }}
        }));
    }
    // Core telemetry remains available offline. A linked template overrides
    // the corresponding collector interval rather than creating duplicates.
    for name in [
        "cpu",
        "memory",
        "filesystem",
        "diskio",
        "network",
        "uptime",
        "self",
    ] {
        if !config.items.iter().any(|item| {
            item.kind == "builtin"
                && serde_json::from_str::<serde_json::Value>(&item.params_json)
                    .ok()
                    .and_then(|p| {
                        p.get("collector")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    })
                    .as_deref()
                    .unwrap_or(&item.key)
                    == name
        }) {
            config.items.push(v1::ItemSpec {
                key: name.into(),
                kind: "builtin".into(),
                interval_s: cfg.interval_s.max(1),
                params_json: format!("{{\"collector\":\"{name}\"}}"),
            });
        }
    }
    for check in desired::checks_from_config(cfg, &config) {
        let dirs = cfg.plugin_dirs.clone();
        let tx = tx.clone();
        let buffer = buffer.clone();
        let id = agent_id.clone();
        let mut stop = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(check.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop { tokio::select! {
                _ = stop.changed() => break,
                _ = tick.tick() => {
                    let now = now_ms();
                    match kestrel_checks::run_command(&check, &dirs, now).await {
                        Ok(out) => {
                            append(&buffer, v1::Batch { checks: vec![v1::CheckResult {check_id:check.id.clone(),state:out.state as i32,output:out.output,perfdata:out.perfdata,timestamp_ms:now}], ..Default::default() }, &id);
                            if tx.send(out.samples).await.is_err() { break; }
                        }
                        Err(err) => tracing::warn!(check=%check.id,error=%err,"command check failed"),
                    }
                }
            }}
        }));
    }
    for item in config.items {
        let params: serde_json::Value = match serde_json::from_str(&item.params_json) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let tx = tx.clone();
        let mut stop = shutdown.clone();
        tasks.push(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(u64::from(item.interval_s.max(1))));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let collector_name=params.get("collector").and_then(|v|v.as_str()).unwrap_or(&item.key);
            let mut collector = if item.kind == "builtin" { builtin_collector(collector_name,&params) } else { None };
            loop { tokio::select! {
                _ = stop.changed() => break,
                _ = tick.tick() => {
                    let now = now_ms();
                    let result = match item.kind.as_str() {
                        "builtin" => {
                            collector.as_mut().and_then(|c|c.collect(now).ok()).unwrap_or_default()
                        }
                        "http" => {
                            let check = HttpCheck {id:item.key.clone(),url:params.get("url").and_then(|v|v.as_str()).unwrap_or("").to_string(),timeout:Duration::from_secs(params.get("timeout_s").and_then(|v|v.as_u64()).unwrap_or(10).clamp(1,300)),body_regex:params.get("body_regex").and_then(|v|v.as_str()).map(str::to_string)};
                            let mut samples = kestrel_checks::run_http_check(&check, now).await.samples;
                            if let Some(job) = params.get("job").and_then(|v|v.as_str()) { for sample in &mut samples { sample.labels.push(("job".into(),job.into())); } }
                            samples
                        }
                        "prometheus" | "prom_scrape" => scrape(&params, now).await.unwrap_or_else(|err| {tracing::warn!(error=%err,"Prometheus scrape failed");vec![]}),
                        _ => vec![],
                    };
                    if !result.is_empty() && tx.send(result).await.is_err() {break;}
                }
            }}
        }));
    }
    tasks
}

fn builtin_collector(name: &str, params: &serde_json::Value) -> Option<Box<dyn Collector>> {
    use kestrel_checks::*;
    Some(match name {
        "cpu" => Box::new(CpuCollector::new()),
        "memory" => Box::new(MemoryCollector::new()),
        "filesystem" => Box::new(FilesystemCollector::new()),
        "diskio" => Box::new(DiskIoCollector::new()),
        "network" => Box::new(NetworkCollector::new()),
        "uptime" => Box::new(UptimeCollector::new()),
        "self" => Box::new(SelfStatsCollector::new()),
        "process" => Box::new(ProcessCollector::new()),
        "service" => Box::new(ServiceCollector::new(
            params
                .get("names")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str()),
        )),
        _ => return None,
    })
}

async fn scrape(
    params: &serde_json::Value,
    now: i64,
) -> Result<Vec<Sample>, Box<dyn std::error::Error + Send + Sync>> {
    let url = params
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("missing scrape URL")?;
    let job = params
        .get("job")
        .and_then(|v| v.as_str())
        .unwrap_or("exporter");
    let instance = params
        .get("instance")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Ok(kestrel_checks::scrape_prometheus(url, job, instance, Duration::from_secs(10), now).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture(url: &str) -> (AgentConfigFile, Arc<Mutex<Buffer>>) {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let dir = std::env::temp_dir().join(format!(
            "kestrel-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let cfg = AgentConfigFile {
            server_url: url.parse().unwrap(),
            data_dir: dir.clone(),
            enrol_token: None,
            bootstrap_ca_path: None,
            interval_s: 30,
            buffer_max_mb: 8,
            labels: BTreeMap::new(),
            allow_remote_commands: false,
            plugin_dirs: vec![],
            prometheus_listen: None,
            config_poll_s: 1,
        };
        let buffer = Arc::new(Mutex::new(
            Buffer::open(dir.join("buffer"), 8 * 1024 * 1024).unwrap(),
        ));
        (cfg, buffer)
    }

    #[tokio::test]
    async fn config_poll_applies_reloads_and_revalidates_etags() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bad"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/good"))
            .respond_with(ResponseTemplate::new(200).set_body_string("healthy"))
            .mount(&server)
            .await;
        let calls = Arc::new(AtomicUsize::new(0));
        let phase = Arc::new(AtomicUsize::new(0));
        let revision = phase.clone();
        let validated = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let revalidated = validated.clone();
        let count = calls.clone();
        let base = server.uri();
        Mock::given(method("GET")).and(path("/api/v1/agent/config")).respond_with(move |request:&wiremock::Request| {
            count.fetch_add(1,Ordering::SeqCst);
            let n=revision.load(Ordering::SeqCst);
            let etag=if n==0 {"\"old\""} else {"\"new\""};
            if request.headers.get("if-none-match").is_some_and(|v|v==etag) {
                if n==1 {revalidated.store(true,Ordering::SeqCst);}
                return ResponseTemplate::new(304);
            }
            let config=v1::AgentConfig {items:vec![v1::ItemSpec{key:"web".into(),kind:"http".into(),interval_s:60,params_json:serde_json::json!({"url":format!("{base}/{}",if n==0 {"bad"}else{"good"})}).to_string()}],..Default::default()};
            ResponseTemplate::new(200).insert_header("ETag",if n==0 {"\"old\""} else {"\"new\""}).set_body_json(config)
        }).mount(&server).await;
        let (cfg, buffer) = fixture(&server.uri());
        let dir = cfg.data_dir.clone();
        let shipper = Arc::new(Shipper::new(&cfg.server_url).unwrap());
        let (tx, mut rx) = mpsc::channel(256);
        let (stop, shutdown) = watch::channel(false);
        let task = tokio::spawn(poll_config(
            cfg,
            shipper,
            tx,
            buffer,
            "agent".into(),
            shutdown,
        ));
        let observations = tokio::time::timeout(Duration::from_secs(15), async {
            let mut values = vec![];
            while values.len() < 2 {
                if let Some(samples) = rx.recv().await {
                    for sample in samples {
                        if sample.name == "kestrel_http_up" {
                            values.push(sample.value);
                            if values.len() == 1 {
                                phase.store(1, Ordering::SeqCst);
                            }
                        }
                    }
                }
            }
            while !validated.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            values
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "configuration polling timed out after {} requests",
                calls.load(Ordering::SeqCst)
            )
        });
        assert_eq!(observations, vec![0.0, 1.0]);
        stop.send(true).unwrap();
        task.await.unwrap();
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.iter().filter(|r| r.url.path() == "/bad").count(),
            1
        );
        assert_eq!(
            requests.iter().filter(|r| r.url.path() == "/good").count(),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn scraper_preserves_exporter_metrics_and_applies_identity() {
        let server = MockServer::start().await;
        Mock::given(path("/metrics"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "node_cpu_seconds_total{cpu=\"0\",mode=\"idle\"} 7\nnode_missing NaN\n",
            ))
            .mount(&server)
            .await;
        let samples=scrape(&serde_json::json!({"url":format!("{}/metrics",server.uri()),"job":"node","instance":"host:9100"}),123).await.unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].value, 7.0);
        assert_eq!(samples[0].timestamp_ms, 123);
        assert!(samples[0]
            .labels
            .contains(&("instance".into(), "host:9100".into())));
    }

    #[tokio::test]
    async fn metrics_endpoint_exposes_the_latest_collected_samples() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reservation.local_addr().unwrap();
        drop(reservation);
        let latest = Arc::new(Mutex::new(BTreeMap::new()));
        let (incoming, rx) = mpsc::channel(8);
        let (tx, mut output) = mpsc::channel(8);
        let forwarding = tokio::spawn(forward_samples(rx, tx, latest.clone()));
        incoming
            .send(vec![Sample {
                name: "kestrel_uptime_seconds".into(),
                labels: vec![("host".into(), "local".into())],
                value: 42.0,
                timestamp_ms: now_ms(),
            }])
            .await
            .unwrap();
        output.recv().await.unwrap();
        let (stop, shutdown) = watch::channel(false);
        let addr_text = addr.to_string();
        let task = tokio::spawn(async move { serve_metrics(&addr_text, latest, shutdown).await });
        let body = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(response) = reqwest::get(format!("http://{addr}/metrics")).await {
                    break response.text().await.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        kestrel_checks::validate_exposition(&body).unwrap();
        assert!(body.contains("kestrel_uptime_seconds{host=\"local\"} 42"));
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        drop(incoming);
        forwarding.await.unwrap();
    }
}
