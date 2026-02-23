use mitm_http::{
    validate_stage_order, DecoderFailureCode, DecoderFrame, DecoderPipelineRegistry, DecoderStage,
    DecoderStageProcessor, DecoderStageStatus, LayeredDecoderPipeline, StageProcessOutcome,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

struct RecordingStage {
    name: &'static str,
    order: Arc<Mutex<Vec<String>>>,
    behavior: RecordingBehavior,
}

enum RecordingBehavior {
    Applied,
    Pending,
    Failed(&'static str),
}

impl DecoderStageProcessor for RecordingStage {
    fn process(&mut self, frame: &DecoderFrame) -> Result<StageProcessOutcome, String> {
        self.order.lock().expect("lock").push(self.name.to_string());
        match self.behavior {
            RecordingBehavior::Applied => Ok(StageProcessOutcome::Applied(frame.clone())),
            RecordingBehavior::Pending => Ok(StageProcessOutcome::Pending(frame.clone())),
            RecordingBehavior::Failed(detail) => Err(detail.to_string()),
        }
    }
}

fn all_stages() -> Vec<DecoderStage> {
    DecoderStage::ORDERED.to_vec()
}

#[test]
fn rejects_out_of_order_stage_lists() {
    let stages = vec![
        DecoderStage::TransferDecode,
        DecoderStage::ProtocolFrameParse,
        DecoderStage::ContentDecode,
    ];
    let err = validate_stage_order(&stages).expect_err("must fail");
    assert_eq!(err.code, DecoderFailureCode::StageOutOfOrder);
    assert_eq!(err.stage, DecoderStage::ContentDecode);
}

#[test]
fn rejects_duplicate_stage_lists() {
    let stages = vec![DecoderStage::TransferDecode, DecoderStage::TransferDecode];
    let err = validate_stage_order(&stages).expect_err("must fail");
    assert_eq!(err.code, DecoderFailureCode::DuplicateStage);
    assert_eq!(err.stage, DecoderStage::TransferDecode);
}

#[test]
fn executes_stages_in_deterministic_order() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut processors = BTreeMap::new();
    for stage in all_stages() {
        processors.insert(
            stage,
            Box::new(RecordingStage {
                name: stage.as_str(),
                order: Arc::clone(&order),
                behavior: RecordingBehavior::Applied,
            }) as Box<dyn DecoderStageProcessor>,
        );
    }

    let mut pipeline = LayeredDecoderPipeline::new(all_stages(), processors).expect("pipeline");
    let result = pipeline.execute(DecoderFrame::new(vec![1, 2, 3], false));
    assert!(result.failure.is_none());
    assert_eq!(result.reports.len(), 5);
    assert!(result
        .reports
        .iter()
        .all(|report| report.status == DecoderStageStatus::Applied));
    let actual = order.lock().expect("lock").clone();
    let expected = all_stages()
        .into_iter()
        .map(|stage| stage.as_str().to_string())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn marks_downstream_stages_as_blocked_after_pending_stage() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut processors = BTreeMap::new();
    let stages = all_stages();
    for (idx, stage) in stages.iter().copied().enumerate() {
        let behavior = if idx == 1 {
            RecordingBehavior::Pending
        } else {
            RecordingBehavior::Applied
        };
        processors.insert(
            stage,
            Box::new(RecordingStage {
                name: stage.as_str(),
                order: Arc::clone(&order),
                behavior,
            }) as Box<dyn DecoderStageProcessor>,
        );
    }

    let mut pipeline = LayeredDecoderPipeline::new(stages, processors).expect("pipeline");
    let result = pipeline.execute(DecoderFrame::new(vec![1, 2, 3], false));
    assert!(result.failure.is_none());
    assert_eq!(result.reports[0].status, DecoderStageStatus::Applied);
    assert_eq!(result.reports[1].status, DecoderStageStatus::Pending);
    assert_eq!(result.reports[2].status, DecoderStageStatus::Blocked);
    assert_eq!(result.reports[3].status, DecoderStageStatus::Blocked);
    assert_eq!(result.reports[4].status, DecoderStageStatus::Blocked);
    let actual = order.lock().expect("lock").clone();
    assert_eq!(actual, vec!["transfer_decode", "content_decode"]);
}

#[test]
fn reports_stage_failure_and_blocks_remaining_stages() {
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut processors = BTreeMap::new();
    let stages = all_stages();
    for (idx, stage) in stages.iter().copied().enumerate() {
        let behavior = if idx == 2 {
            RecordingBehavior::Failed("boom")
        } else {
            RecordingBehavior::Applied
        };
        processors.insert(
            stage,
            Box::new(RecordingStage {
                name: stage.as_str(),
                order: Arc::clone(&order),
                behavior,
            }) as Box<dyn DecoderStageProcessor>,
        );
    }

    let mut pipeline = LayeredDecoderPipeline::new(stages, processors).expect("pipeline");
    let result = pipeline.execute(DecoderFrame::new(vec![1, 2, 3], false));
    let failure = result.failure.expect("failure");
    assert_eq!(failure.code, DecoderFailureCode::StageFailed);
    assert_eq!(failure.stage, DecoderStage::ProtocolFrameParse);
    assert_eq!(result.reports[0].status, DecoderStageStatus::Applied);
    assert_eq!(result.reports[1].status, DecoderStageStatus::Applied);
    assert_eq!(result.reports[2].status, DecoderStageStatus::Failed);
    assert_eq!(result.reports[3].status, DecoderStageStatus::Blocked);
    assert_eq!(result.reports[4].status, DecoderStageStatus::Blocked);
    let actual = order.lock().expect("lock").clone();
    assert_eq!(
        actual,
        vec![
            "transfer_decode".to_string(),
            "content_decode".to_string(),
            "protocol_frame_parse".to_string(),
        ]
    );
}

#[test]
fn registry_keeps_validated_stage_sets() {
    let mut registry = DecoderPipelineRegistry::default();
    registry
        .register("grpc", all_stages())
        .expect("register grpc");
    let stages = registry.stages_for("grpc").expect("stages");
    assert_eq!(stages, DecoderStage::ORDERED.as_slice());
}
