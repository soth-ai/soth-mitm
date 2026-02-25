#![cfg_attr(not(target_env = "msvc"), no_main)]

use std::collections::BTreeMap;

#[cfg(not(target_env = "msvc"))]
use libfuzzer_sys::fuzz_target;
use mitm_http::{
    DecoderFailureCode, DecoderFrame, DecoderPipelineResult, DecoderStage, DecoderStageProcessor,
    DecoderStageStatus, LayeredDecoderPipeline, StageProcessOutcome,
};

struct FuzzStageProcessor {
    stage: DecoderStage,
    mode: u8,
}

impl DecoderStageProcessor for FuzzStageProcessor {
    fn process(&mut self, frame: &DecoderFrame) -> Result<StageProcessOutcome, String> {
        let mut next = frame.clone();
        next.attributes.insert(
            format!("stage_{}", self.stage.as_str()),
            self.mode.to_string(),
        );

        match self.mode % 5 {
            0 => {
                next.bytes.push(self.mode);
                Ok(StageProcessOutcome::Applied(next))
            }
            1 => Ok(StageProcessOutcome::Pending(next)),
            2 => Err(format!("fuzz-stage-error-{}", self.stage.as_str())),
            3 => {
                next.bytes.reverse();
                Ok(StageProcessOutcome::Applied(next))
            }
            _ => Ok(StageProcessOutcome::Applied(next)),
        }
    }
}

fn run_decoder_layering_case(data: &[u8]) {
    let stage_count = (data.first().copied().unwrap_or(0) as usize % 6).max(1);
    let mut stages = Vec::with_capacity(stage_count);
    for idx in 0..stage_count {
        let seed = data.get(1 + idx).copied().unwrap_or(0);
        let stage = match seed % 5 {
            0 => DecoderStage::TransferDecode,
            1 => DecoderStage::ContentDecode,
            2 => DecoderStage::ProtocolFrameParse,
            3 => DecoderStage::EnvelopeParse,
            _ => DecoderStage::PayloadParse,
        };
        stages.push(stage);
    }

    let mut processors: BTreeMap<DecoderStage, Box<dyn DecoderStageProcessor>> = BTreeMap::new();
    for (idx, stage) in stages.iter().enumerate() {
        let seed = data.get(8 + idx).copied().unwrap_or(0);
        if seed % 7 == 0 {
            continue;
        }
        processors.insert(
            *stage,
            Box::new(FuzzStageProcessor {
                stage: *stage,
                mode: seed,
            }),
        );
    }

    let payload = data.iter().skip(32).copied().collect::<Vec<_>>();
    let frame = DecoderFrame::new(payload, data.len() % 2 == 0);

    let mut pipeline = match LayeredDecoderPipeline::new(stages.clone(), processors) {
        Ok(pipeline) => pipeline,
        Err(failure) => {
            assert!(
                failure.code == DecoderFailureCode::DuplicateStage
                    || failure.code == DecoderFailureCode::StageOutOfOrder
            );
            return;
        }
    };

    let result = pipeline.execute(frame);
    assert_decoder_pipeline_invariants(&stages, &result);
}

#[cfg(not(target_env = "msvc"))]
fuzz_target!(|data: &[u8]| {
    run_decoder_layering_case(data);
});

#[cfg(target_env = "msvc")]
fn main() {
    let mut saw_input = false;
    for arg in std::env::args().skip(1) {
        if arg.starts_with('-') {
            continue;
        }
        let path = std::path::Path::new(&arg);
        if !path.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let input_path = entry.path();
                if !input_path.is_file() {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&input_path) {
                    run_decoder_layering_case(&bytes);
                    saw_input = true;
                }
            }
        }
    }
    if !saw_input {
        run_decoder_layering_case(br#"{"seed":"decoder-layering"}"#);
    }
}

fn assert_decoder_pipeline_invariants(stages: &[DecoderStage], result: &DecoderPipelineResult) {
    assert_eq!(result.reports.len(), stages.len());

    let mut saw_pending_or_failed = false;
    for (idx, report) in result.reports.iter().enumerate() {
        assert_eq!(report.stage, stages[idx]);
        match report.status {
            DecoderStageStatus::Applied => {
                if saw_pending_or_failed {
                    panic!("applied stage observed after pending/failed stage");
                }
            }
            DecoderStageStatus::Pending => {
                saw_pending_or_failed = true;
                assert!(report.failure.is_none());
            }
            DecoderStageStatus::Failed => {
                saw_pending_or_failed = true;
                assert!(report.failure.is_some());
            }
            DecoderStageStatus::Blocked => {
                assert!(saw_pending_or_failed);
                assert!(report.failure.is_none());
            }
        }
    }

    if let Some(failure) = result.failure.as_ref() {
        assert!(result.reports.iter().any(|report| {
            report.status == DecoderStageStatus::Failed
                && report
                    .failure
                    .as_ref()
                    .map(|value| value.code == failure.code)
                    .unwrap_or(false)
        }));
    }
}
