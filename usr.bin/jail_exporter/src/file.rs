// file: File exporter
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
use crate::errors::ExporterError;
use crate::exporter::Exporter;
use std::fmt;
use std::io::{
    self,
    Write,
};
use std::path::PathBuf;
use tempfile::NamedTempFile;
use tracing::debug;

#[derive(Clone, Debug)]
pub enum FileExporterOutput {
    File(PathBuf),
    Stdout,
}

impl fmt::Display for FileExporterOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::File(path) => {
                let path = path.to_str().expect("path to str");
                write!(f, "{path}")
            },
            Self::Stdout => write!(f, "-"),
        }
    }
}

pub struct FileExporter {
    dest: FileExporterOutput,
}

impl FileExporter {
    pub fn new(output: FileExporterOutput) -> Self {
        debug!("New FileExporter output to: {output}");

        Self {
            dest: output,
        }
    }

    // Handles choosing the correct output type based on path
    fn write(&self, metrics: &str) -> Result<(), ExporterError> {
        debug!("Writing metrics to: {}", self.dest);

        match &self.dest {
            FileExporterOutput::Stdout => {
                io::stdout().write_all(metrics.as_bytes())?;
            },
            FileExporterOutput::File(path) => {
                // We already vetted the parent in the CLI validator, so unwrap
                // here should be fine.
                let parent = path.parent().expect("path to have a parent");

                // We do this since we need the temporary file to be on the
                // same filesystem as the final persisted file.
                let mut file = NamedTempFile::new_in(parent)?;
                file.write_all(metrics.as_bytes())?;
                file.persist(path)?;
            },
        }

        Ok(())
    }

    pub fn export(self) -> Result<(), ExporterError> {
        debug!("Exporting metrics to file");

        // Get an exporter and export the metrics.
        let exporter = Exporter::new();
        let metrics  = exporter.export()?;

        // Write metrics
        self.write(&metrics)?;

        Ok(())
    }
}
