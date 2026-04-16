use crate::approvals::cli::Tty;
use crate::approvals::dispatcher::DualChannelDispatcher;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

pub async fn bridge<T: Tty + 'static>(
    dispatcher: Arc<DualChannelDispatcher<T>>,
    mut symbi_rx: mpsc::Receiver<(
        symbi_runtime::reasoning::human_critic::ReviewRequest,
        oneshot::Sender<symbi_runtime::reasoning::human_critic::ReviewResponse>,
    )>,
) {
    use symbi_runtime::reasoning::human_critic::{CriticResult, ReviewResponse, ReviewerIdentity};

    while let Some((req, response_tx)) = symbi_rx.recv().await {
        let d = dispatcher.clone();
        tokio::spawn(async move {
            let (bool_tx, bool_rx) = oneshot::channel();
            d.handle_one(
                req.review_id.clone(),
                req.context.clone(),
                req.deadline,
                bool_tx,
            )
            .await;
            let approved = bool_rx.await.unwrap_or(false);
            let result = CriticResult {
                approved,
                score: if approved { 1.0 } else { 0.0 },
                dimension_scores: Default::default(),
                feedback: if approved {
                    "approved".into()
                } else {
                    "denied or expired".into()
                },
                reviewer: ReviewerIdentity::Human {
                    user_id: "redteam-operator".into(),
                    name: "operator".into(),
                },
            };
            let _ = response_tx.send(ReviewResponse {
                review_id: req.review_id,
                result,
            });
        });
    }
}
