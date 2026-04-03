use clap::Parser;

#[derive(Parser)]
#[command(name = "abrasive", version, about = "The Abrasive CLI")]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    println!("Hello, world 4!");
}
