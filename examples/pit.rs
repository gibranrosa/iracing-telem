use std::time::Duration;

use iracing_telem::flags::{BroadcastMsg, PitCommand};

fn main() -> Result<(), iracing_telem::safe::SafeError> {
    let mut c = iracing_telem::safe::Client::new();
    println!("Start iRacing");
    match c.wait_for_session(Duration::new(600, 0))? {
        None => {
            println!("Remember to start iRacing");
        }
        Some(s) => {
            s.broadcast_msg(BroadcastMsg::PitCommand(PitCommand::Fuel(Some(5))))?;
            s.broadcast_msg(BroadcastMsg::PitCommand(PitCommand::LR(Some(150))))?;
        }
    }
    Ok(())
}
