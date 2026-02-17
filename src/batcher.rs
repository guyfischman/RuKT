use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, Duration};
use crate::tree::{Tree, PreUpdateData, PostUpdateData};
use crate::proto::transparency::{SignedUpdateRequest, UpdateResponse};
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::Mutex;

const MAX_BATCH_SIZE: usize = 100;
const BATCH_TIMEOUT: Duration = Duration::from_millis(50);

pub struct UpdateJob {
    pub req: SignedUpdateRequest,
    pub resp_tx: oneshot::Sender<Result<UpdateResponse>>,
}

pub struct Batcher {
    tx: mpsc::Sender<UpdateJob>,
}

impl Batcher {
    pub fn new(tree: Arc<Mutex<Tree>>) -> Self {
        let (tx, rx) = mpsc::channel(MAX_BATCH_SIZE * 10);
        
        let mut worker = BatchWorker {
            tree,
            rx,
        };

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
    tree: Arc<Mutex<Tree>>,
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
                            // Check for tombstone update (has expected_pre_update_value)
                            let is_tombstone = if let Some(r) = &job.req.request {
                                !r.expected_pre_update_value.is_empty()
                            } else { false };

                            if is_tombstone {
                                // 1. Flush existing batch first to preserve order
                                if !batch.is_empty() {
                                    self.process_batch(&mut batch).await;
                                }
                                
                                // 2. Process tombstone immediately as a singleton batch
                                batch.push(job);
                                self.process_batch(&mut batch).await;

                                // Reset timer
                                sleep.as_mut().reset(tokio::time::Instant::now() + BATCH_TIMEOUT);
                            } else {
                                // Standard update accumulation
                                batch.push(job);
                                if batch.len() >= MAX_BATCH_SIZE {
                                    self.process_batch(&mut batch).await;
                                    sleep.as_mut().reset(tokio::time::Instant::now() + BATCH_TIMEOUT);
                                }
                            }
                        }
                        None => break, // Channel closed
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

        let mut tree_guard = self.tree.lock().await;
        
        let start_size = tree_guard.latest.as_ref().map(|th| th.tree_size).unwrap_or(0);
        
        let mut pre_data_list: Vec<PreUpdateData> = Vec::new();
        let mut jobs_to_process = Vec::new();

        let all_jobs: Vec<UpdateJob> = batch.drain(..).collect();
        
        for (i, job) in all_jobs.into_iter().enumerate() {
            let pos = start_size + i as u64;
            // Pre-calculate crypto (VRF, Commitments)
            // Note: If this is a tombstone singleton batch, logic holds.
            match tree_guard.pre_update(job.req.clone(), pos) {
                Ok(data) => {
                    pre_data_list.push(data);
                    jobs_to_process.push(job);
                },
                Err(e) => {
                    let _ = job.resp_tx.send(Err(e));
                }
            }
        }

        if pre_data_list.is_empty() {
            return;
        }

        // Apply Batch
        // Now returns a list of results corresponding to inputs, enabling individual failures
        match tree_guard.apply_batch(pre_data_list.clone()).await {
            Ok((results, _new_head)) => {
                for (i, result) in results.into_iter().enumerate() {
                    let job = jobs_to_process.remove(0); 
                    
                    match result {
                        Ok(post_data) => {
                            let pre = pre_data_list[i].clone();
                            let resp = tree_guard.post_update(pre, post_data).await;
                            let _ = job.resp_tx.send(resp);
                        },
                        Err(e) => {
                            // Example: Tombstone mismatch error
                            let _ = job.resp_tx.send(Err(e));
                        }
                    }
                }
            }
            Err(e) => {
                // Catastrophic failure (e.g. DB IO error) - fail all
                for job in jobs_to_process {
                    let _ = job.resp_tx.send(Err(anyhow!("Batch commit failed: {}", e)));
                }
            }
        }
    }
}