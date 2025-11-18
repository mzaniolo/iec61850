# IEC 61850

A pure rust implementation of the [IEC61850 protocol](https://es.wikipedia.org/wiki/IEC_61850).

This crate provides a client that implements the IEC61850 MMS part of the protocol. Goose and sv parts may come in the future. A server implementation may also come in the future. Basic tests where done using a test server but some error may still arise. Despite the client being already working this is still a work in progress and the interfaces may change.

## Usage

A more complete example of how to use the client can be found on the examples folder.

```rust
use iec61850::{
 ClientConfig, Iec61850Client,
 mms::ReportCallback,
};

/// A test report callback that will print the report to the console.
struct TestReportCallback;

#[async_trait::async_trait]
impl ReportCallback for TestReportCallback {
 async fn on_report(&self, report: Report) {
  println!("Report: {:?}", report);
 }
}


#[tokio::main]
async fn main() -> Result<(), dyn std::error::Error> {
    // Connects to a server at localhost:102. Configurations like the serve ip and port can be changed using the ClientConfig
    let client = Iec61850Client::new(ClientConfig::default(), Box::new(TestReportCallback)).await?;

    let model = client.model();
    println!("Ied model: {model:#?}");

    let data = client
  .read_data_from_ld("SampleIEDDevice1", &["DGEN1$ST$Mod", "DGEN1$MX$TotWh"])
  .await?;
 println!("Data: {data:#?}");
}
```

## Contributing

Contributions are welcome and encourage!

If a bug is found open and issue explaining the problem and, if possible, attach some package captures to help understanding the problem.

## Pre-commit usage

A set of [pre-commits](https://pre-commit.com) hooks are provided to help keep the code nice and tidy

1. If not installed, install with your package manager, or `pip install --user pre-commit`
2. Run `pre-commit autoupdate` to update the pre-commit config to use the newest template
3. Run `pre-commit install` to install the pre-commit hooks to your local environment
