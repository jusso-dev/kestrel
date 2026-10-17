//! Real PostgreSQL/VictoriaMetrics/mTLS throughput probe. Run in a container
//! limited to four CPUs. DATABASE_URL must allow creation of a test database.
use kestrel_agent::{config::AgentConfigFile, identity, shipper::Shipper};
use kestrel_proto::v1::{Batch, Label, Sample};
use kestrel_server::{
    config::{CaConfig, ServerConfigFile, TlsConfig},
    db::Db,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;
type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let opts = PgConnectOptions::from_str(&std::env::var("DATABASE_URL")?)?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts.clone())
        .await?;
    let name = format!("kestrel_load_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(opts.database(&name))
        .await?;
    let db = Db::from_pool(pool.clone()).await?;
    let dir = std::env::temp_dir().join(&name);
    std::fs::create_dir_all(&dir)?;
    let outcome:Result<(),Error>=async {
        let victoria=Url::parse(&std::env::var("VICTORIA_URL")?)?;
        // Raise only the configured quota to measure capacity, rather than the
        // intentional default 50k/s admission limit. Restore is unnecessary:
        // the entire isolated database is removed below.
        sqlx::query("UPDATE tenants SET samples_per_second=10000000").execute(&pool).await?;
        let cfg=ServerConfigFile{listen:"127.0.0.1:0".parse()?,ingest_listen:None,database_url:String::new(),victoria_url:victoria.clone(),tls:TlsConfig{cert_path:dir.join("server.crt"),key_path:dir.join("server.key")},ca:CaConfig{cert_path:dir.join("ca.crt"),key_path:dir.join("ca.key")},public_url:Url::parse("https://127.0.0.1")?,smtp:None,data_dir:dir.join("server"),log_retention_days:7,otlp_drop_attributes:vec!["user_id".into()]};
        let server=kestrel_server::start_with(cfg,Some(db.clone())).await?;
        let server_url=Url::parse(&format!("https://{}/",server.addr))?;
        let concurrency=32u64;let batches=100u64;let batch_size=1000u64;
        let mut clients=Vec::new();
        for n in 0..concurrency{
            let token=kestrel_server::admin::create_token(&dir.join("server"),None,Duration::from_secs(600))?;
            let cfg=AgentConfigFile{server_url:server_url.clone(),data_dir:dir.join(format!("agent-{n}")),enrol_token:Some(token),bootstrap_ca_path:Some(dir.join("ca.crt")),interval_s:30,buffer_max_mb:16,labels:BTreeMap::new(),allow_remote_commands:false,plugin_dirs:Vec::new(),prometheus_listen:None,config_poll_s:60};
            let identity=identity::ensure(&cfg).await?.ok_or("agent did not enrol")?;
            clients.push((Arc::new(Shipper::with_identity(&server_url,&identity.client_identity())?),identity.agent_id));
        }
        let start=Instant::now();let mut jobs=tokio::task::JoinSet::new();
        for (client,agent_id) in clients{
            let run_label=name.clone();
            jobs.spawn(async move{
                for seq in 1..=batches{
                    let timestamp_ms=chrono::Utc::now().timestamp_millis();
                    let samples=(0..batch_size).map(|slot|Sample{name:"kestrel_ingest_load".into(),labels:vec![Label{name:"slot".into(),value:slot.to_string()},Label{name:"load_run".into(),value:run_label.clone()}],value:seq as f64,timestamp_ms}).collect();
                    let bytes=kestrel_proto::encode_batch(&Batch{agent_id:agent_id.clone(),seq,samples,..Default::default()});
                    loop{
                        match client.post_bytes(bytes.clone()).await?{
                            200=>break,429=>tokio::time::sleep(Duration::from_millis(10)).await,
                            status=>return Err::<(),Error>(format!("ingest returned {status}").into()),
                        }
                    }
                }
                Ok::<(),Error>(())
            });
        }
        while let Some(job)=jobs.join_next().await{job??;}
        let elapsed=start.elapsed().as_secs_f64();let count=concurrency*batches*batch_size;
        let rate=count as f64/elapsed;
        println!("samples={count} duration_s={elapsed:.3} samples_per_second={rate:.0} agents={concurrency} batch_size={batch_size} db_pool=5");
        let persisted:i64=sqlx::query_scalar("SELECT sum(last_seq)::bigint FROM agents").fetch_one(&pool).await?;
        assert_eq!(persisted,(concurrency*batches) as i64,"all committed sequences persisted");
        let http=reqwest::Client::new();let mut queryable=false;
        for _ in 0..50{
            let selector=format!("kestrel_ingest_load{{load_run=\"{name}\"}}");
            let body:serde_json::Value=http.get(victoria.join("api/v1/query")?).query(&[("query",selector.as_str())]).send().await?.json().await?;
            if body.pointer("/data/result").and_then(serde_json::Value::as_array).is_some_and(|items|items.iter().any(|item|item.pointer("/metric/tenant").is_some()&&item.pointer("/metric/host").is_some())){queryable=true;break;}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(queryable,"samples must be queryable with tenant and host labels");
        server.shutdown();drop(server);
        if rate<50000.0{return Err(format!("below 50000 samples/s target: {rate:.0}").into());}
        Ok(())
    }.await;
    drop(db);
    if let Ok(base) = std::env::var("VICTORIA_URL")
        .and_then(|s| Url::parse(&s).map_err(|_| std::env::VarError::NotPresent))
    {
        if let Ok(url) = base.join("api/v1/admin/tsdb/delete_series") {
            let selector = format!("kestrel_ingest_load{{load_run=\"{name}\"}}");
            let _ = reqwest::Client::new()
                .post(url)
                .query(&[("match[]", selector)])
                .send()
                .await;
        }
    }
    pool.close().await;
    sqlx::raw_sql(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await?;
    let _ = std::fs::remove_dir_all(dir);
    outcome
}
