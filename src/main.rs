mod sniffer;
mod cli;

use cli::Cli;

fn main() {
    let mut cli = Cli::new();
    cli.run();
}
