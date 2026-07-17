use crate::proto::transparency::{UpdateRequest, UpdateResponse};
use crate::tree::{PreUpdateData, Tree};
use anyhow::{Result, anyhow};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::{self, Duration};

const MAX_BATCH_SIZE: usize = 4000;
const BATCH_TIMEOUT: Duration = Duration::from_millis(50);

pub struct UpdateJob {
    pub req: UpdateRequest,
    pub resp_tx: oneshot::Sender<Result<UpdateResponse>>,
}

pub struct Batcher {
    tx: mpsc::Sender<UpdateJob>,
}

impl Batcher {
    pub fn new(tree: Arc<RwLock<Tree>>) -> Self {
        let (tx, rx) = mpsc::channel(MAX_BATCH_SIZE * 10);
        let mut worker = BatchWorker { tree, rx };

        tokio::spawn(async move {
            worker.run().await;
        });

        Self { tx }
    }

    pub async fn submit(&self, req: UpdateRequest) -> Result<UpdateResponse> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(UpdateJob { req, resp_tx })
            .await
            .map_err(|_| anyhow!("Batcher worker is down"))?;

        resp_rx
            .await
            .map_err(|_| anyhow!("Batcher dropped response"))?
    }
}

struct BatchWorker {
    tree: Arc<RwLock<Tree>>,
    rx: mpsc::Receiver<UpdateJob>,
}

impl BatchWorker {
    async fn run(&mut self) {
        let mut batch: Vec<UpdateJob> = Vec::with_capacity(MAX_BATCH_SIZE);
        let sleep = time::sleep(BATCH_TIMEOUT);
        tokio::pin!(sleep);

        loop {
            tokio::select! {
                msg = self.rx.recv() => {
                    match msg {
                        Some(job) => {
                            batch.push(job);
                            if batch.len() >= MAX_BATCH_SIZE {
                                self.process_batch(&mut batch).await;
                                sleep.as_mut().reset(tokio::time::Instant::now() + BATCH_TIMEOUT);
                            }
                        }
                        None => break,
                    }
                }
                _ = &mut sleep => {
                    if !batch.is_empty() {
                        self.process_batch(&mut batch).await;
                    }
                    sleep.as_mut().reset(tokio::time::Instant::now() + BATCH_TIMEOUT);
                }
            }
        }
    }

    async fn process_catchups(&self, jobs: Vec<UpdateJob>) {
        if jobs.is_empty() {
            return;
        }
        let mut tasks = Vec::new();
        for job in jobs {
            let tree_arc = self.tree.clone();
            tasks.push(tokio::spawn(async move {
                let read_guard = tree_arc.read().await;
                let resp = read_guard.catch_up_update(&job.req).await;
                let _ = job.resp_tx.send(resp);
            }));
        }
        futures::future::join_all(tasks).await;
    }

    async fn process_batch(&mut self, batch: &mut Vec<UpdateJob>) {
        if batch.is_empty() {
            return;
        }

        let batch_size = batch.len();
        let t_total = Instant::now();

        // ==========================================
        // PHASE 1: Sequential Versioning
        // ==========================================
        let t1 = Instant::now();
        let mut tree_guard = self.tree.write().await;
        let mut jobs_to_process = Vec::new();
        let all_jobs: Vec<UpdateJob> = std::mem::take(batch);

        let mut pre_jobs = Vec::new();
        let mut version_overlay: std::collections::HashMap<Vec<u8>, u32> =
            std::collections::HashMap::new();

        let mut catchup_jobs = Vec::new();

        for job in all_jobs {
            let req = &job.req;

            let current_greatest: Option<u32> =
                version_overlay.get(&req.label).copied().or_else(|| {
                    tree_guard
                        .store
                        .get_label_history(&req.label)
                        .unwrap_or_default()
                        .last()
                        .map(|(v, _)| *v)
                });

            // §13.5 compare-and-swap on greatest_version
            if req.greatest_version != current_greatest {
                let behind = match (req.greatest_version, current_greatest) {
                    (None, Some(_)) => true,
                    (Some(claimed), Some(actual)) => claimed < actual,
                    _ => false,
                };
                if behind {
                    catchup_jobs.push(job);
                } else {
                    let _ = job.resp_tx.send(Err(anyhow::Error::new(
                        crate::tree::errors::KtError::VersionConflict,
                    )));
                }
                continue;
            }
            if req.values.is_empty() {
                let _ = job.resp_tx.send(Err(anyhow!(
                    "Empty values: no versions exist beyond the advertised greatest_version"
                )));
                continue;
            }

            let start_ver = current_greatest.map(|v| v + 1).unwrap_or(0);
            let versions: Vec<u32> = (0..req.values.len() as u32)
                .map(|k| start_ver + k)
                .collect();
            version_overlay.insert(req.label.clone(), *versions.last().unwrap());

            pre_jobs.push((req.clone(), versions));
            jobs_to_process.push(job);
        }
        let dur_p1 = t1.elapsed();

        if jobs_to_process.is_empty() && catchup_jobs.is_empty() {
            return;
        }

        if jobs_to_process.is_empty() {
            drop(tree_guard);
            self.process_catchups(catchup_jobs).await;
            return;
        }

        // ==========================================
        // PHASE 2: Parallel Cryptography
        // ==========================================
        let t2 = Instant::now();
        let config = tree_guard.config.clone();
        let mut crypto_tasks = Vec::new();
        let mut job_ranges: Vec<std::ops::Range<usize>> = Vec::with_capacity(pre_jobs.len());
        let mut offset = 0usize;

        for (req, versions) in pre_jobs {
            job_ranges.push(offset..offset + versions.len());
            offset += versions.len();

            for (k, version) in versions.into_iter().enumerate() {
                let cfg = config.clone();
                let label = req.label.clone();
                let value = req.values[k].value.clone();
                let last = req.last.unwrap_or(0);
                crypto_tasks.push(tokio::task::spawn_blocking(move || {
                    let (index, vrf_proof) = cfg.vrf_prove(&label, version).unwrap();
                    let opening = crate::crypto::generate_random_opening();
                    let commitment =
                        crate::crypto::commit(&label, version, &value, None, &opening).unwrap();

                    PreUpdateData {
                        label,
                        value,
                        last,
                        version,
                        index,
                        vrf_proof,
                        commitment,
                        opening,
                    }
                }));
            }
        }

        let mut pre_data_list = Vec::new();
        for res in futures::future::join_all(crypto_tasks).await {
            pre_data_list.push(res.unwrap());
        }
        let dur_p2 = t2.elapsed();

        // ==========================================
        // PHASE 3: Sequential Merkle Append (DB Writes)
        // ==========================================
        let t3 = Instant::now();
        let apply_result = tree_guard.apply_batch(pre_data_list.clone()).await;
        let dur_p3 = t3.elapsed();

        // 🔥 DROP THE EXCLUSIVE WRITE LOCK EARLY 🔥
        // This allows all cores to generate user proofs simultaneously
        drop(tree_guard);

        self.process_catchups(catchup_jobs).await;

        // ==========================================
        // PHASE 4: Parallel Proof Generation (DB Reads)
        // ==========================================
        let t4 = Instant::now();
        match apply_result {
            Ok((results, _new_head)) => {
                let tree_arc = self.tree.clone();
                let mut proof_tasks = Vec::new();
                let mut results: Vec<Option<Result<crate::tree::PostUpdateData>>> =
                    results.into_iter().map(Some).collect();

                for (job, range) in jobs_to_process.into_iter().zip(job_ranges) {
                    let pres: Vec<PreUpdateData> = pre_data_list[range.clone()].to_vec();
                    let mut group: Vec<Result<crate::tree::PostUpdateData>> =
                        range.map(|i| results[i].take().unwrap()).collect();

                    if let Some(err_idx) = group.iter().position(|r| r.is_err()) {
                        let e = match group.swap_remove(err_idx) {
                            Err(e) => e,
                            Ok(_) => unreachable!(),
                        };
                        let _ = job.resp_tx.send(Err(e));
                        continue;
                    }

                    let post_data = group.pop().unwrap().unwrap();
                    let t_arc = tree_arc.clone();

                    // Spawn a task that acquires a READ lock concurrently
                    proof_tasks.push(tokio::spawn(async move {
                        let read_guard = t_arc.read().await;
                        let resp = read_guard.post_update(&pres, post_data).await;
                        let _ = job.resp_tx.send(resp);
                    }));
                }

                // Await all parallel proof generation
                futures::future::join_all(proof_tasks).await;
            }
            Err(e) => {
                for job in jobs_to_process {
                    let _ = job
                        .resp_tx
                        .send(Err(anyhow::anyhow!("Batch commit failed: {}", e)));
                }
            }
        }
        let dur_p4 = t4.elapsed();

        println!(
            "⚡ Batch [{}] | Total: {:.2?} | P1(Setup): {:.2?} | P2(Crypto): {:.2?} | P3(Writes): {:.2?} | P4(Proofs): {:.2?}",
            batch_size,
            t_total.elapsed(),
            dur_p1,
            dur_p2,
            dur_p3,
            dur_p4
        );
    }
}
