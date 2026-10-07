use crate::cli::AuthArgs;
use nm_app::AppService;
use nm_core::DeviceId;
use nm_store::repo::DeviceRepo;
use std::path::Path;
pub async fn execute(
    svc: &AppService,
    device: DeviceId,
    out: &Path,
    auth: &AuthArgs,
    json: bool,
) -> anyhow::Result<u8> {
    let device = DeviceRepo::new(&svc.db)
        .get(device)?
        .ok_or_else(|| anyhow::anyhow!("device not found"))?;
    anyhow::ensure!(
        device.enrolled,
        "fixture capture requires explicit enrollment"
    );
    let collector = svc
        .collectors
        .get(device.family)
        .ok_or_else(|| anyhow::anyhow!("collector unavailable"))?;
    super::scan::load_credentials(svc, std::slice::from_ref(&device), auth).await?;
    let ctx = svc
        .collect_context(tokio_util::sync::CancellationToken::new())
        .await?;
    let result = if let Ok(result) = tokio::time::timeout(
        ctx.limits.per_device_budget,
        collector.collect(&ctx, &device),
    )
    .await
    {
        result?
    } else {
        let mut result = ctx
            .partial
            .lock()
            .map_err(|_| anyhow::anyhow!("partial result lock poisoned"))?
            .get(&device.id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("capture budget expired before any artifacts"))?;
        result.coverage.missing = result
            .coverage
            .expected
            .iter()
            .filter(|c| {
                !result.coverage.collected.contains(c) && !result.coverage.skipped.contains_key(*c)
            })
            .cloned()
            .collect();
        result.outcome = nm_core::Outcome::Partial(result.coverage.missing.clone());
        result
    };
    anyhow::ensure!(
        !result.raw.is_empty(),
        "capture collected no artifacts: {:?} {:?}",
        result.outcome,
        result.coverage.errors
    );
    std::fs::create_dir_all(out)?;
    let mut tokenizer = nm_collect::scrub::FixtureTokenizer::default();
    for raw in &result.raw {
        let (bytes, _) = nm_collect::scrub::scrub_secrets(device.family, &raw.name, &raw.bytes);
        let bytes = tokenizer.tokenize(&bytes);
        std::fs::write(out.join(&raw.name), bytes)?;
    }
    let quote = |s: &str| serde_json::to_string(s).expect("string serialization");
    let metadata=format!("model = {}\nfirmware = {}\nrole = {}\ncapture_date = {}\nsynthetic = false\npartial = {}\n",quote(result.facts.system.model.as_deref().unwrap_or("unknown")),quote(result.facts.system.firmware.as_deref().unwrap_or("unknown")),quote(&device.role.map_or_else(|| "unknown".into(), |r|format!("{r:?}").to_lowercase())),quote(&nm_core::Timestamp::now().to_string()),serde_json::to_string(&result.coverage.missing)?);
    std::fs::write(out.join("meta.toml"), metadata)?;
    svc.audit.flush().await?;
    eprintln!("Review every captured file before committing.");
    if json {
        println!(
            "{}",
            serde_json::json!({"type":"summary","out":out,"artifacts":result.raw.len(),"outcome":result.outcome})
        );
    }
    Ok(if result.outcome == nm_core::Outcome::Ok {
        0
    } else {
        4
    })
}
