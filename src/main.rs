use std::io::{self, Read};

use clap::Parser;
use command_obfuscator::{AllModules, OS, Pipeline};

#[derive(Parser)]
#[command(
    name = "boo",
    about = "Bash obfuscation tool",
    long_about = "Bash obfuscation tool with optional EDR evasion modules.\n\n\
        Default modules: Quotes, Hex, Param (applied with -m or no -m flag).\n\n\
        EDR evasion modules (opt-in only, must be explicitly requested):\n  \
          base64   - wraps command in base64-encoded pipe\n  \
          varindir - splits command across random variables + eval\n  \
          exec     - wraps command in exec bash -c (process mask)\n  \
          heredoc  - wraps command in a bash heredoc"
)]
struct Args {
    /// Command to obfuscate (reads from stdin if omitted)
    #[arg(short, long)]
    command: Option<String>,

    /// Modules to apply (default: Quotes,Hex,Param).
    /// Add EDR evasion: -m base64,varindir,exec,heredoc
    #[arg(short, long, value_enum, num_args = 1.., value_delimiter = ',')]
    module: Option<Vec<AllModules>>,
}

fn main() {
    let args = Args::parse();

    let command = match args.command {
        Some(c) => c,
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .expect("failed to read stdin");
            buf.trim_end_matches('\n').to_string()
        }
    };

    let modules: Vec<AllModules> = args.module.unwrap_or_else(AllModules::all);

    let mut pipeline = Pipeline::new(OS::Linux);
    for m in modules {
        pipeline = pipeline.add(m);
    }

    println!(r##"{}"##, pipeline.run(&command));
}
