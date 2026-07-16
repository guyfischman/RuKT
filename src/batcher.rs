use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time::{self, Duration};
use crate::tree::{Tree, PreUpdateData};
use crate::proto::transparency::{SignedUpdateRequest, UpdateResponse};
use anyhow::{Result, anyhow};
use std::sync::Arc;
use std::time::Instant;

const MAX_BATCH_SIZE: usize = 4000;
const BATCH_TIMEOUT: Duration = Duration::from_millis(50);

pub struct UpdateJob {
    pub req: SignedUpdateRequest,
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

    pub async fn submit(&self, req: SignedUpdateRequest) -> Result<UpdateResponse> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx.send(UpdateJob { req, resp_tx }).await
            .map_err(|_| anyhow!("Batcher worker is down"))?;
            
        resp_rx.await.map_err(|_| anyhow!("Batcher dropped response"))?
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

    async fn process_batch(&mut self, batch: &mut Vec<UpdateJob>) {
        if batch.is_empty() { return; }
        
        let batch_size = batch.len();
        let t_total = Instant::now();

        // ==========================================
        // PHASE 1: Sequential Versioning
        // ==========================================
        let t1 = Instant::now();
        let mut tree_guard = self.tree.write().await;
        let mut jobs_to_process = Vec::new();
        let all_jobs: Vec<UpdateJob> = batch.drain(..).collect();
        
        let mut pre_jobs = Vec::new();
        let mut version_overlay = std::collections::HashMap::new();

        for job in all_jobs {
            let inner_req = job.req.request.as_ref().unwrap();
            
            let current_ver = if let Some(&v) = version_overlay.get(&inner_req.search_key) {
                v
            } else {
                let history = tree_guard.store.get_label_history(&inner_req.search_key).unwrap_or_default();
                history.last().map(|(v, _)| *v).unwrap_or(0)
            };

            let history_empty = tree_guard.store.get_label_history(&inner_req.search_key).unwrap_or_default().is_empty();
            let next_ver = if current_ver == 0 && history_empty && !version_overlay.contains_key(&inner_req.search_key) {
                0
            } else {
                current_ver + 1
            };
            
            version_overlay.insert(inner_req.search_key.clone(), next_ver);
            pre_jobs.push((job.req.clone(), next_ver));
            jobs_to_process.push(job);
        }
        let dur_p1 = t1.elapsed();

        if jobs_to_process.is_empty() { return; }

        // ==========================================
        // PHASE 2: Parallel Cryptography
        // ==========================================
        let t2 = Instant::now();
        let config = tree_guard.config.clone();
        let mut crypto_tasks = Vec::new();

        for (req, next_version) in pre_jobs {
            let cfg = config.clone();
            crypto_tasks.push(tokio::task::spawn_blocking(move || {
                let inner = req.request.clone().unwrap();
                let (index, vrf_proof) = cfg.vrf_prove(&inner.search_key, next_version).unwrap();
                let opening = crate::crypto::generate_random_opening();
                let commitment = crate::crypto::commit(&inner.search_key, next_version, &inner.value, &opening).unwrap();

                PreUpdateData {
                    req: inner,
                    signature: req.signature.clone(),
                    version: next_version,
                    index,
                    vrf_proof,
                    commitment,
                    opening,
                }
            }));
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

        // ==========================================
        // PHASE 4: Parallel Proof Generation (DB Reads)
        // ==========================================
        let t4 = Instant::now();
        match apply_result {
            Ok((results, _new_head)) => {
                let tree_arc = self.tree.clone();
                let mut proof_tasks = Vec::new();

                for (i, result) in results.into_iter().enumerate() {
                    let job = jobs_to_process.remove(0); 
                    let pre = pre_data_list[i].clone();
                    let t_arc = tree_arc.clone();

                    // Spawn a task that acquires a READ lock concurrently
                    proof_tasks.push(tokio::spawn(async move {
                        match result {
                            Ok(post_data) => {
                                // Safe to run concurrently across 2000 tasks
                                let read_guard = t_arc.read().await;
                                let resp = read_guard.post_update(pre, post_data).await;
                                let _ = job.resp_tx.send(resp);
                            },
                            Err(e) => { let _ = job.resp_tx.send(Err(e)); }
                        }
                    }));
                }
                
                // Await all parallel proof generation
                futures::future::join_all(proof_tasks).await;
            }
            Err(e) => {
                for job in jobs_to_process {
                    let _ = job.resp_tx.send(Err(anyhow::anyhow!("Batch commit failed: {}", e)));
                }
            }
        }
        let dur_p4 = t4.elapsed();

        println!("⚡ Batch [{}] | Total: {:.2?} | P1(Setup): {:.2?} | P2(Crypto): {:.2?} | P3(Writes): {:.2?} | P4(Proofs): {:.2?}", 
            batch_size, t_total.elapsed(), dur_p1, dur_p2, dur_p3, dur_p4);
    }
}