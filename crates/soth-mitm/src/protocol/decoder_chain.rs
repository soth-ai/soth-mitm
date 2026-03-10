use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecoderStage {
    TransferDecode,
    ContentDecode,
    ProtocolFrameParse,
    EnvelopeParse,
    PayloadParse,
}

impl DecoderStage {
    pub const ORDERED: [Self; 5] = [
        Self::TransferDecode,
        Self::ContentDecode,
        Self::ProtocolFrameParse,
        Self::EnvelopeParse,
        Self::PayloadParse,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransferDecode => "transfer_decode",
            Self::ContentDecode => "content_decode",
            Self::ProtocolFrameParse => "protocol_frame_parse",
            Self::EnvelopeParse => "envelope_parse",
            Self::PayloadParse => "payload_parse",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderFailureCode {
    StageOutOfOrder,
    DuplicateStage,
    MissingStageProcessor,
    StageFailed,
}

impl DecoderFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StageOutOfOrder => "stage_out_of_order",
            Self::DuplicateStage => "duplicate_stage",
            Self::MissingStageProcessor => "missing_stage_processor",
            Self::StageFailed => "stage_failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderStageStatus {
    Applied,
    Pending,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderFrame {
    pub bytes: Vec<u8>,
    pub end_of_stream: bool,
    pub attributes: BTreeMap<String, String>,
}

impl DecoderFrame {
    pub fn new(bytes: Vec<u8>, end_of_stream: bool) -> Self {
        Self {
            bytes,
            end_of_stream,
            attributes: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderStageFailure {
    pub stage: DecoderStage,
    pub code: DecoderFailureCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderStageReport {
    pub stage: DecoderStage,
    pub status: DecoderStageStatus,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub failure: Option<DecoderStageFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoderPipelineResult {
    pub output: DecoderFrame,
    pub reports: Vec<DecoderStageReport>,
    pub failure: Option<DecoderStageFailure>,
}

pub enum StageProcessOutcome {
    Applied(DecoderFrame),
    Pending(DecoderFrame),
}

pub trait DecoderStageProcessor: Send {
    fn process(&mut self, frame: &DecoderFrame) -> Result<StageProcessOutcome, String>;
}

pub struct LayeredDecoderPipeline {
    stages: Vec<DecoderStage>,
    processors: BTreeMap<DecoderStage, Box<dyn DecoderStageProcessor>>,
}

impl LayeredDecoderPipeline {
    pub fn new(
        stages: Vec<DecoderStage>,
        processors: BTreeMap<DecoderStage, Box<dyn DecoderStageProcessor>>,
    ) -> Result<Self, DecoderStageFailure> {
        validate_stage_order(&stages)?;
        Ok(Self { stages, processors })
    }

    pub fn execute(&mut self, mut frame: DecoderFrame) -> DecoderPipelineResult {
        let mut reports = Vec::with_capacity(self.stages.len());
        let mut blocked = false;
        let mut first_failure: Option<DecoderStageFailure> = None;

        for stage in &self.stages {
            let bytes_in = frame.bytes.len();
            if blocked {
                reports.push(DecoderStageReport {
                    stage: *stage,
                    status: DecoderStageStatus::Blocked,
                    bytes_in,
                    bytes_out: bytes_in,
                    failure: None,
                });
                continue;
            }

            let Some(processor) = self.processors.get_mut(stage) else {
                let failure = DecoderStageFailure {
                    stage: *stage,
                    code: DecoderFailureCode::MissingStageProcessor,
                    detail: format!("no processor registered for stage {}", stage.as_str()),
                };
                reports.push(DecoderStageReport {
                    stage: *stage,
                    status: DecoderStageStatus::Failed,
                    bytes_in,
                    bytes_out: bytes_in,
                    failure: Some(failure.clone()),
                });
                first_failure = Some(failure);
                blocked = true;
                continue;
            };

            match processor.process(&frame) {
                Ok(StageProcessOutcome::Applied(next)) => {
                    let bytes_out = next.bytes.len();
                    frame = next;
                    reports.push(DecoderStageReport {
                        stage: *stage,
                        status: DecoderStageStatus::Applied,
                        bytes_in,
                        bytes_out,
                        failure: None,
                    });
                }
                Ok(StageProcessOutcome::Pending(next)) => {
                    let bytes_out = next.bytes.len();
                    frame = next;
                    reports.push(DecoderStageReport {
                        stage: *stage,
                        status: DecoderStageStatus::Pending,
                        bytes_in,
                        bytes_out,
                        failure: None,
                    });
                    blocked = true;
                }
                Err(detail) => {
                    let failure = DecoderStageFailure {
                        stage: *stage,
                        code: DecoderFailureCode::StageFailed,
                        detail,
                    };
                    reports.push(DecoderStageReport {
                        stage: *stage,
                        status: DecoderStageStatus::Failed,
                        bytes_in,
                        bytes_out: bytes_in,
                        failure: Some(failure.clone()),
                    });
                    first_failure = Some(failure);
                    blocked = true;
                }
            }
        }

        DecoderPipelineResult {
            output: frame,
            reports,
            failure: first_failure,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecoderPipelineRegistry {
    stage_sets: BTreeMap<String, Vec<DecoderStage>>,
}

impl DecoderPipelineRegistry {
    pub fn register(
        &mut self,
        key: impl Into<String>,
        stages: Vec<DecoderStage>,
    ) -> Result<(), DecoderStageFailure> {
        validate_stage_order(&stages)?;
        self.stage_sets.insert(key.into(), stages);
        Ok(())
    }

    pub fn stages_for(&self, key: &str) -> Option<&[DecoderStage]> {
        self.stage_sets.get(key).map(Vec::as_slice)
    }
}

pub fn validate_stage_order(stages: &[DecoderStage]) -> Result<(), DecoderStageFailure> {
    let mut seen = HashSet::new();
    let mut last_index = None;

    for stage in stages {
        if !seen.insert(*stage) {
            return Err(DecoderStageFailure {
                stage: *stage,
                code: DecoderFailureCode::DuplicateStage,
                detail: format!("stage {} appears more than once", stage.as_str()),
            });
        }

        let index = DecoderStage::ORDERED
            .iter()
            .position(|candidate| candidate == stage)
            .expect("ordered stage list must include all variants");
        if let Some(previous) = last_index {
            if index < previous {
                return Err(DecoderStageFailure {
                    stage: *stage,
                    code: DecoderFailureCode::StageOutOfOrder,
                    detail: format!("stage {} violated pipeline ordering", stage.as_str()),
                });
            }
        }
        last_index = Some(index);
    }

    Ok(())
}
