use std::fmt;

use snafu::Snafu;

use tracing_error::SpanTrace;

pub mod ans1;
pub mod cotp;
pub mod session;

#[derive(Debug)]
pub struct SpanTraceWrapper(SpanTrace);

impl snafu::GenerateImplicitData for Box<SpanTraceWrapper> {
    fn generate() -> Self {
        Box::new(SpanTraceWrapper(SpanTrace::capture()))
    }
}

impl fmt::Display for SpanTraceWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.status() == tracing_error::SpanTraceStatus::CAPTURED {
            write!(f, "\nAt:\n")?;
            self.0.fmt(f)?;
        }
        Ok(())
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(false)))]
pub enum Error {
    #[snafu(whatever, display("{message}{context}\n{source:?}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error + Send + Sync>, Some)))]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        #[snafu(implicit)]
        context: Box<SpanTraceWrapper>,
    },
}
